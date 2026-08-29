import "server-only";

import { and, desc, eq, inArray, isNull } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  encryptedVaultRecordSchema,
  type EncryptedVaultRecord,
} from "@/lib/crypto/vault";
import { assertOperationalMetadataSafe } from "@/lib/domain/privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import type { VaultRotationRequest } from "@/lib/domain/vault-lifecycle";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { requireOrganizationRole, requireOrganizationRoleWith } from "./repository";
import {
  auditEvents,
  organizationMembers,
  organizations,
  vaultKeyGrants,
  vaultRecords,
} from "./schema";

export const ENCRYPTED_RECORD_TYPES = [
  "principal",
  "payee",
  "pay-agreement",
  "payroll-run",
  "payroll-line",
  "proof-bundle",
  "settlement",
  "receipt",
  "disclosure-grant",
  "agent-capability",
  "wage-claim",
  "remediation",
] as const;

export type EncryptedRecordType = (typeof ENCRYPTED_RECORD_TYPES)[number];

function auditId(): string {
  return generateUuidV7();
}

function assertEnvelopeIdentity(input: {
  organizationId: string;
  recordId: string;
  recordType: EncryptedRecordType;
  revision: number;
  envelope: EncryptedVaultRecord;
}): void {
  const { aad } = input.envelope;
  if (
    aad.organizationId !== input.organizationId
    || aad.recordId !== input.recordId
    || aad.recordType !== input.recordType
    || aad.revision !== input.revision
  ) {
    throw new ApiError(400, "Encrypted record AAD does not match its storage identity.", "AAD_MISMATCH");
  }
}

function safeAuditMetadata(metadata: Record<string, unknown>) {
  assertOperationalMetadataSafe(metadata);
  return metadata;
}

export async function storeEncryptedVaultRevision(input: {
  organizationId: string;
  recordId: string;
  recordType: EncryptedRecordType;
  revision: number;
  envelope: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
}) {
  const [stored] = await storeEncryptedVaultRevisions({
    organizationId: input.organizationId,
    records: [{
      recordId: input.recordId,
      recordType: input.recordType,
      revision: input.revision,
      envelope: input.envelope,
    }],
    principal: input.principal,
  });
  return stored;
}

export async function storeEncryptedVaultRevisions(input: {
  organizationId: string;
  records: Array<{
    recordId: string;
    recordType: EncryptedRecordType;
    revision: number;
    envelope: EncryptedVaultRecord;
  }>;
  principal: AuthenticatedPrincipal;
}) {
  if (input.records.length < 1 || input.records.length > 100) {
    throw new ApiError(400, "An encrypted record batch must contain 1–100 records.", "RECORD_BATCH_SIZE_INVALID");
  }
  const identities = input.records.map(({ recordId, revision }) => `${recordId}:${revision}`);
  if (new Set(identities).size !== identities.length) {
    throw new ApiError(400, "An encrypted record batch contains duplicate identities.", "RECORD_BATCH_DUPLICATE");
  }
  const records = input.records.map((record) => {
    const envelope = encryptedVaultRecordSchema.parse(record.envelope);
    return { ...record, envelope, envelopeHash: hashCanonicalJson(envelope) };
  });
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin", "operator"]);
    for (const record of records) {
      assertEnvelopeIdentity({ ...record, organizationId: input.organizationId });
    }
    const results = [];
    for (const record of records) {
      const [existingRevision] = await transaction
        .select({ envelopeHash: vaultRecords.envelopeHash, createdAt: vaultRecords.createdAt })
        .from(vaultRecords)
        .where(and(
          eq(vaultRecords.organizationId, input.organizationId),
          eq(vaultRecords.id, record.recordId),
          eq(vaultRecords.revision, record.revision),
        ))
        .limit(1);
      if (existingRevision) {
        if (existingRevision.envelopeHash !== record.envelopeHash) {
          throw new ApiError(409, "This encrypted record revision already contains different data.", "RECORD_REVISION_CONFLICT");
        }
        results.push({
          id: record.recordId,
          revision: record.revision,
          envelopeHash: record.envelopeHash,
          createdAt: existingRevision.createdAt,
          replayed: true,
        });
        continue;
      }
      const [latest] = await transaction
        .select({ revision: vaultRecords.revision })
        .from(vaultRecords)
        .where(and(eq(vaultRecords.organizationId, input.organizationId), eq(vaultRecords.id, record.recordId)))
        .orderBy(desc(vaultRecords.revision))
        .limit(1);
      const expectedRevision = latest ? latest.revision + 1 : 1;
      if (record.revision !== expectedRevision) {
        throw new ApiError(409, `Encrypted record revision must be ${expectedRevision}.`, "RECORD_REVISION_GAP");
      }
      if (latest) {
        await transaction
          .update(vaultRecords)
          .set({ supersededAt: new Date() })
          .where(and(
            eq(vaultRecords.organizationId, input.organizationId),
            eq(vaultRecords.id, record.recordId),
            eq(vaultRecords.revision, latest.revision),
          ));
      }
      const [stored] = await transaction
        .insert(vaultRecords)
        .values({
          id: record.recordId,
          organizationId: input.organizationId,
          recordType: record.recordType,
          revision: record.revision,
          ciphertext: record.envelope.ciphertext,
          envelope: record.envelope,
          envelopeHash: record.envelopeHash,
          createdBy: input.principal.principalId,
        })
        .returning({ createdAt: vaultRecords.createdAt });
      await transaction.insert(auditEvents).values({
        id: auditId(),
        organizationId: input.organizationId,
        actorId: input.principal.principalId,
        action: "vault_record.revision_stored",
        subjectId: record.recordId,
        metadata: safeAuditMetadata({
          recordType: record.recordType,
          revision: record.revision,
          envelopeHash: record.envelopeHash,
        }),
      });
      results.push({
        id: record.recordId,
        revision: record.revision,
        envelopeHash: record.envelopeHash,
        createdAt: stored.createdAt,
        replayed: false,
      });
    }
    return results;
  });
}

export async function getEncryptedVaultRecord(input: {
  organizationId: string;
  recordId: string;
  revision?: number;
  principal: AuthenticatedPrincipal;
}) {
  await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator", "reviewer"]);
  const where = input.revision === undefined
    ? and(eq(vaultRecords.organizationId, input.organizationId), eq(vaultRecords.id, input.recordId))
    : and(
      eq(vaultRecords.organizationId, input.organizationId),
      eq(vaultRecords.id, input.recordId),
      eq(vaultRecords.revision, input.revision),
    );
  const [record] = await getDatabase()
    .select({
      id: vaultRecords.id,
      recordType: vaultRecords.recordType,
      revision: vaultRecords.revision,
      envelope: vaultRecords.envelope,
      envelopeHash: vaultRecords.envelopeHash,
      createdAt: vaultRecords.createdAt,
    })
    .from(vaultRecords)
    .where(where)
    .orderBy(desc(vaultRecords.revision))
    .limit(1);
  if (!record) throw new ApiError(404, "Encrypted record not found.", "VAULT_RECORD_NOT_FOUND");
  return record;
}

export async function listEncryptedVaultRecords(input: {
  organizationId: string;
  recordType?: EncryptedRecordType;
  principal: AuthenticatedPrincipal;
}) {
  await requireOrganizationRole(input.organizationId, input.principal, ["admin", "operator", "reviewer"]);
  const rows = await getDatabase()
    .select({
      id: vaultRecords.id,
      recordType: vaultRecords.recordType,
      revision: vaultRecords.revision,
      envelopeHash: vaultRecords.envelopeHash,
      supersededAt: vaultRecords.supersededAt,
      createdAt: vaultRecords.createdAt,
    })
    .from(vaultRecords)
    .where(input.recordType
      ? and(eq(vaultRecords.organizationId, input.organizationId), eq(vaultRecords.recordType, input.recordType))
      : eq(vaultRecords.organizationId, input.organizationId))
    .orderBy(vaultRecords.id, desc(vaultRecords.revision));
  const seen = new Set<string>();
  return rows.filter((row) => {
    if (seen.has(row.id)) return false;
    seen.add(row.id);
    return true;
  });
}

export async function acknowledgeRecoveryPackage(input: {
  organizationId: string;
  packageHash: string;
  principal: AuthenticatedPrincipal;
}) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(input.packageHash)) {
    throw new ApiError(400, "A canonical recovery-package hash is required.", "RECOVERY_HASH_INVALID");
  }
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    const [organization] = await transaction
      .update(organizations)
      .set({
        recoveryState: "package_downloaded",
        recoveryPackageHash: input.packageHash.toLowerCase(),
        recoveryConfiguredAt: new Date(),
      })
      .where(eq(organizations.id, input.organizationId))
      .returning({
        id: organizations.id,
        recoveryState: organizations.recoveryState,
        recoveryConfiguredAt: organizations.recoveryConfiguredAt,
      });
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    await transaction.insert(auditEvents).values({
      id: auditId(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "vault_recovery.package_acknowledged",
      subjectId: input.organizationId,
      metadata: safeAuditMetadata({ packageHash: input.packageHash.toLowerCase() }),
    });
    return organization;
  });
}

export async function getOrganizationVaultState(
  organizationId: string,
  principal: AuthenticatedPrincipal,
) {
  await requireOrganizationRole(organizationId, principal, ["admin", "operator", "reviewer"]);
  const database = getDatabase();
  const [organization] = await database
    .select({
      id: organizations.id,
      recoveryState: organizations.recoveryState,
      recoveryConfiguredAt: organizations.recoveryConfiguredAt,
      keyVersion: organizations.keyVersion,
    })
    .from(organizations)
    .where(eq(organizations.id, organizationId))
    .limit(1);
  if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
  const members = await database
    .select({
      principalId: organizationMembers.principalId,
      role: organizationMembers.role,
      vaultPublicKey: organizationMembers.vaultPublicKey,
      keyVersion: organizationMembers.keyVersion,
      revokedAt: organizationMembers.revokedAt,
    })
    .from(organizationMembers)
    .where(eq(organizationMembers.organizationId, organizationId));
  return { ...organization, members };
}

export async function addSecondAdministrator(input: {
  organizationId: string;
  grantId: string;
  granteePrincipalId: string;
  vaultPublicKey: string;
  keyVersion: number;
  envelope: EncryptedVaultRecord;
  encryptedProfile: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
}) {
  const envelope = encryptedVaultRecordSchema.parse(input.envelope);
  const encryptedProfile = encryptedVaultRecordSchema.parse(input.encryptedProfile);
  if (
    envelope.aad.organizationId !== input.organizationId
    || envelope.aad.recordType !== "vault-key-grant"
    || envelope.aad.recordId !== input.grantId
    || envelope.aad.revision !== input.keyVersion
    || !envelope.wrappedKeys.some(({ principalId }) => principalId === input.granteePrincipalId)
  ) {
    throw new ApiError(400, "Second-admin grant identity or wrapped key is invalid.", "VAULT_GRANT_INVALID");
  }
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    if (input.granteePrincipalId === input.principal.principalId) {
      throw new ApiError(400, "A second administrator must be another principal.", "SECOND_ADMIN_REQUIRED");
    }
    const [organization] = await transaction
      .select({
        keyVersion: organizations.keyVersion,
        encryptedProfile: organizations.encryptedProfile,
      })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1)
      .for("update");
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.keyVersion !== input.keyVersion) {
      throw new ApiError(409, "The organization key changed; create a new second-admin grant.", "KEY_VERSION_CONFLICT");
    }
    const currentProfile = encryptedVaultRecordSchema.parse(organization.encryptedProfile);
    if (
      encryptedProfile.aad.organizationId !== input.organizationId
      || encryptedProfile.aad.recordType !== "organization-profile"
      || encryptedProfile.aad.recordId !== input.organizationId
      || encryptedProfile.ciphertext !== currentProfile.ciphertext
      || !encryptedProfile.wrappedKeys.some(({ principalId }) => principalId === input.principal.principalId)
      || !encryptedProfile.wrappedKeys.some(({ principalId }) => principalId === input.granteePrincipalId)
    ) {
      throw new ApiError(400, "The rewrapped organization profile is invalid.", "PROFILE_REWRAP_INVALID");
    }
    const [existingMember] = await transaction
      .select({ revokedAt: organizationMembers.revokedAt })
      .from(organizationMembers)
      .where(and(
        eq(organizationMembers.organizationId, input.organizationId),
        eq(organizationMembers.principalId, input.granteePrincipalId),
      ))
      .limit(1)
      .for("update");
    if (existingMember) {
      throw new ApiError(409, "This principal already has an organization membership.", "MEMBER_EXISTS");
    }
    await transaction.insert(organizationMembers).values({
      organizationId: input.organizationId,
      principalId: input.granteePrincipalId,
      role: "admin",
      vaultPublicKey: input.vaultPublicKey,
      keyVersion: input.keyVersion,
    });
    const [grant] = await transaction.insert(vaultKeyGrants).values({
      id: input.grantId,
      organizationId: input.organizationId,
      granteePrincipalId: input.granteePrincipalId,
      keyVersion: input.keyVersion,
      envelope,
      envelopeHash: hashCanonicalJson(envelope),
      createdBy: input.principal.principalId,
    }).returning({
      id: vaultKeyGrants.id,
      keyVersion: vaultKeyGrants.keyVersion,
      createdAt: vaultKeyGrants.createdAt,
    });
    await transaction.update(organizations).set({
      encryptedProfile,
      recoveryState: "second_admin",
      recoveryConfiguredAt: new Date(),
    }).where(eq(organizations.id, input.organizationId));
    await transaction.insert(auditEvents).values({
      id: auditId(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "vault_recovery.second_admin_added",
      subjectId: input.granteePrincipalId,
      metadata: safeAuditMetadata({ grantId: input.grantId, keyVersion: input.keyVersion }),
    });
    return grant;
  });
}

export async function getCurrentVaultKeyGrant(input: {
  organizationId: string;
  principal: AuthenticatedPrincipal;
}) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    const [organization] = await transaction
      .select({ keyVersion: organizations.keyVersion })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1);
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    const [grant] = await transaction
      .select({
        id: vaultKeyGrants.id,
        keyVersion: vaultKeyGrants.keyVersion,
        envelope: vaultKeyGrants.envelope,
        createdAt: vaultKeyGrants.createdAt,
      })
      .from(vaultKeyGrants)
      .where(and(
        eq(vaultKeyGrants.organizationId, input.organizationId),
        eq(vaultKeyGrants.granteePrincipalId, input.principal.principalId),
        eq(vaultKeyGrants.keyVersion, organization.keyVersion),
        isNull(vaultKeyGrants.revokedAt),
      ))
      .limit(1);
    if (!grant) throw new ApiError(404, "No active vault-key grant exists for this administrator.", "VAULT_GRANT_NOT_FOUND");
    return grant;
  });
}

export async function rotateOrganizationVault(input: {
  organizationId: string;
  rotation: VaultRotationRequest;
  principal: AuthenticatedPrincipal;
}) {
  const { rotation } = input;
  if (rotation.revokePrincipalIds.includes(input.principal.principalId)) {
    throw new ApiError(400, "The rotating administrator cannot revoke itself.", "SELF_REVOCATION_FORBIDDEN");
  }
  if (new Set(rotation.revokePrincipalIds).size !== rotation.revokePrincipalIds.length) {
    throw new ApiError(400, "Revoked principal IDs must be unique.", "REVOCATION_DUPLICATE");
  }
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    const [organization] = await transaction
      .select({ keyVersion: organizations.keyVersion, encryptedProfile: organizations.encryptedProfile })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1)
      .for("update");
    if (!organization) throw new ApiError(404, "Organization not found.", "ORG_NOT_FOUND");
    if (organization.keyVersion !== rotation.expectedKeyVersion) {
      throw new ApiError(409, "The vault key changed; restart rotation.", "KEY_VERSION_CONFLICT");
    }
    const nextKeyVersion = organization.keyVersion + 1;
    const members = await transaction
      .select()
      .from(organizationMembers)
      .where(and(
        eq(organizationMembers.organizationId, input.organizationId),
        isNull(organizationMembers.revokedAt),
      ))
      .for("update");
    const activeAfterRotation = members.filter(({ principalId }) =>
      !rotation.revokePrincipalIds.includes(principalId));
    const activeIds = new Set(activeAfterRotation.map(({ principalId }) => principalId));
    const activeAdmins = activeAfterRotation.filter(({ role }) => role === "admin");
    if (activeAdmins.length === 0) {
      throw new ApiError(400, "Vault rotation must retain an active administrator.", "LAST_ADMIN_REQUIRED");
    }
    for (const principalId of rotation.revokePrincipalIds) {
      if (!members.some((member) => member.principalId === principalId)) {
        throw new ApiError(400, "A revoked principal is not an active organization member.", "MEMBER_NOT_ACTIVE");
      }
    }

    const currentProfile = encryptedVaultRecordSchema.parse(organization.encryptedProfile);
    const nextProfile = encryptedVaultRecordSchema.parse(rotation.encryptedProfile);
    if (
      nextProfile.aad.organizationId !== input.organizationId
      || nextProfile.aad.recordType !== "organization-profile"
      || nextProfile.aad.recordId !== input.organizationId
      || nextProfile.aad.revision <= currentProfile.aad.revision
      || nextProfile.ciphertext === currentProfile.ciphertext
    ) {
      throw new ApiError(400, "Vault rotation requires a fresh organization-profile DEK and revision.", "PROFILE_ROTATION_INVALID");
    }
    const profileRecipients = new Set(nextProfile.wrappedKeys.map(({ principalId }) => principalId));
    if (!profileRecipients.has(input.principal.principalId)
      || [...profileRecipients].some((principalId) => !activeIds.has(principalId))) {
      throw new ApiError(400, "The rotated profile contains an inactive or incomplete recipient set.", "PROFILE_RECIPIENT_INVALID");
    }
    for (const wrapped of currentProfile.wrappedKeys) {
      if (activeIds.has(wrapped.principalId) && !profileRecipients.has(wrapped.principalId)) {
        throw new ApiError(400, "Vault rotation would remove an active profile recipient.", "PROFILE_RECIPIENT_MISSING");
      }
    }

    const allRecords = await transaction
      .select()
      .from(vaultRecords)
      .where(eq(vaultRecords.organizationId, input.organizationId))
      .orderBy(vaultRecords.id, desc(vaultRecords.revision))
      .for("update");
    const latestRecords = allRecords.filter((record, index) =>
      record.recordType !== "obligation-claim-access"
      && record.recordType !== "wage-claim-v2"
      && (index === 0 || allRecords[index - 1].id !== record.id));
    const rotatedById = new Map(rotation.records.map((record) => [record.recordId, record]));
    if (rotatedById.size !== rotation.records.length || rotatedById.size !== latestRecords.length) {
      throw new ApiError(400, "Vault rotation must include every latest encrypted record exactly once.", "ROTATION_COVERAGE_INVALID");
    }
    for (const current of latestRecords) {
      const rotated = rotatedById.get(current.id);
      if (!rotated || rotated.recordType !== current.recordType || rotated.revision !== current.revision + 1) {
        throw new ApiError(400, `Vault record ${current.id} has an invalid rotation revision.`, "ROTATION_REVISION_INVALID");
      }
      const envelope = encryptedVaultRecordSchema.parse(rotated.envelope);
      if (
        envelope.aad.organizationId !== input.organizationId
        || envelope.aad.recordId !== current.id
        || envelope.aad.recordType !== current.recordType
        || envelope.aad.revision !== rotated.revision
        || envelope.ciphertext === current.ciphertext
      ) {
        throw new ApiError(400, `Vault record ${current.id} was not re-encrypted under a fresh DEK.`, "ROTATION_ENVELOPE_INVALID");
      }
      const recipients = new Set(envelope.wrappedKeys.map(({ principalId }) => principalId));
      if (!recipients.has(input.principal.principalId)
        || [...recipients].some((principalId) => !activeIds.has(principalId))) {
        throw new ApiError(400, `Vault record ${current.id} contains an inactive recipient.`, "ROTATION_RECIPIENT_INVALID");
      }
      const previous = encryptedVaultRecordSchema.parse(current.envelope);
      for (const wrapped of previous.wrappedKeys) {
        if (activeIds.has(wrapped.principalId) && !recipients.has(wrapped.principalId)) {
          throw new ApiError(400, `Vault record ${current.id} would remove an active recipient.`, "ROTATION_RECIPIENT_MISSING");
        }
      }
    }

    const grantsByPrincipal = new Map(rotation.grants.map((grant) => [grant.granteePrincipalId, grant]));
    const grantRecipients = activeAdmins
      .filter(({ principalId }) => principalId !== input.principal.principalId)
      .map(({ principalId }) => principalId);
    if (grantsByPrincipal.size !== rotation.grants.length
      || grantsByPrincipal.size !== grantRecipients.length
      || grantRecipients.some((principalId) => !grantsByPrincipal.has(principalId))) {
      throw new ApiError(400, "Vault rotation requires one fresh grant for every other active administrator.", "ROTATION_GRANT_COVERAGE_INVALID");
    }
    for (const [granteePrincipalId, grant] of grantsByPrincipal) {
      const envelope = encryptedVaultRecordSchema.parse(grant.envelope);
      if (
        envelope.aad.organizationId !== input.organizationId
        || envelope.aad.recordType !== "vault-key-grant"
        || envelope.aad.recordId !== grant.grantId
        || envelope.aad.revision !== nextKeyVersion
        || envelope.wrappedKeys.length !== 1
        || envelope.wrappedKeys[0].principalId !== granteePrincipalId
      ) {
        throw new ApiError(400, "A rotated vault-key grant is invalid.", "ROTATION_GRANT_INVALID");
      }
    }

    const rotationTime = new Date();
    for (const current of latestRecords) {
      const rotated = rotatedById.get(current.id)!;
      const envelope = encryptedVaultRecordSchema.parse(rotated.envelope);
      await transaction
        .update(vaultRecords)
        .set({ supersededAt: rotationTime })
        .where(and(
          eq(vaultRecords.organizationId, input.organizationId),
          eq(vaultRecords.id, current.id),
          eq(vaultRecords.revision, current.revision),
        ));
      await transaction.insert(vaultRecords).values({
        id: current.id,
        organizationId: input.organizationId,
        recordType: current.recordType,
        revision: rotated.revision,
        ciphertext: envelope.ciphertext,
        envelope,
        envelopeHash: hashCanonicalJson(envelope),
        createdBy: input.principal.principalId,
      });
    }
    await transaction
      .update(vaultKeyGrants)
      .set({ revokedAt: rotationTime })
      .where(and(eq(vaultKeyGrants.organizationId, input.organizationId), isNull(vaultKeyGrants.revokedAt)));
    for (const grant of rotation.grants) {
      await transaction.insert(vaultKeyGrants).values({
        id: grant.grantId,
        organizationId: input.organizationId,
        granteePrincipalId: grant.granteePrincipalId,
        keyVersion: nextKeyVersion,
        envelope: grant.envelope,
        envelopeHash: hashCanonicalJson(grant.envelope),
        createdBy: input.principal.principalId,
      });
    }
    if (rotation.revokePrincipalIds.length > 0) {
      await transaction
        .update(organizationMembers)
        .set({ revokedAt: rotationTime })
        .where(and(
          eq(organizationMembers.organizationId, input.organizationId),
          inArray(organizationMembers.principalId, rotation.revokePrincipalIds),
          isNull(organizationMembers.revokedAt),
        ));
    }
    await transaction
      .update(organizationMembers)
      .set({ keyVersion: nextKeyVersion })
      .where(and(eq(organizationMembers.organizationId, input.organizationId), isNull(organizationMembers.revokedAt)));
    const [updated] = await transaction
      .update(organizations)
      .set({
        encryptedProfile: nextProfile,
        keyVersion: nextKeyVersion,
        recoveryPackageHash: rotation.recoveryPackageHash.toLowerCase(),
        recoveryConfiguredAt: rotationTime,
        recoveryState: activeAdmins.length > 1 ? "second_admin" : "package_downloaded",
      })
      .where(and(
        eq(organizations.id, input.organizationId),
        eq(organizations.keyVersion, rotation.expectedKeyVersion),
      ))
      .returning({ keyVersion: organizations.keyVersion, recoveryState: organizations.recoveryState });
    if (!updated) throw new ApiError(409, "The vault key changed during rotation.", "KEY_VERSION_CONFLICT");
    await transaction.insert(auditEvents).values({
      id: auditId(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "vault.key_rotated",
      subjectId: input.organizationId,
      metadata: safeAuditMetadata({
        previousKeyVersion: rotation.expectedKeyVersion,
        keyVersion: nextKeyVersion,
        rotatedRecordCount: latestRecords.length,
        revokedPrincipalIds: rotation.revokePrincipalIds,
      }),
    });
    return updated;
  });
}
