"use client";

import { useLogin, usePrivy } from "@privy-io/react-auth";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { PayoClient } from "@/lib/client/payo-client";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  createVaultWorkspace,
  unlockVaultWorkspace,
} from "@/lib/client/vault-workspace";
import {
  vaultRecoveryPackageSchema,
  vaultSecondAdminEnrollmentSchema,
  type VaultPrincipalKeyPair,
  type VaultRecoveryPackage,
  type VaultSecondAdminEnrollment,
} from "@/lib/crypto/vault";
import {
  finishSecondAdminRecovery,
  prepareSecondAdminGrant,
} from "@/lib/client/vault-admin";
import { createSecondAdminEnrollment } from "@/lib/crypto/vault";
import type { EncryptedVaultRecord } from "@/lib/crypto/vault";
import { rotateClientVault } from "@/lib/client/vault-rotation";

type OrganizationSummary = {
  id: string;
  recoveryState: "required" | "package_downloaded" | "second_admin";
  keyVersion: number;
  role: "admin" | "operator" | "reviewer";
  encryptedProfile: EncryptedVaultRecord;
  vaultPublicKey: string;
  createdAt: string;
};

export type VaultSession = {
  organizationId: string;
  organizationSecret: string;
  principal: VaultPrincipalKeyPair;
};

export type PayoVaultContextValue = {
  configured: boolean;
  ready: boolean;
  authenticated: boolean;
  principalId: string;
  organizations: OrganizationSummary[];
  selectedOrganizationId: string;
  session: VaultSession | null;
  recoveryReady: boolean;
  loading: boolean;
  error: string;
  client: PayoClient | null;
  login: () => void;
  selectOrganization: (organizationId: string) => void;
  createWorkspace: (organizationName: string, recoveryPassword: string) => Promise<void>;
  unlockWorkspace: (password: string) => Promise<void>;
  importRecoveryPackage: (packageInput: unknown) => void;
  downloadRecoveryPackage: () => void;
  confirmRecoverySaved: () => Promise<void>;
  createSecondAdminRequest: (organizationId: string, password: string) => Promise<void>;
  addSecondAdministrator: (enrollment: unknown) => Promise<void>;
  rotateVault: (newRecoveryPassword: string, revokePrincipalIds?: readonly string[]) => Promise<void>;
  lockWorkspace: () => void;
  refreshOrganizations: () => Promise<void>;
};

const unavailableValue: PayoVaultContextValue = {
  configured: false,
  ready: true,
  authenticated: false,
  principalId: "",
  organizations: [],
  selectedOrganizationId: "",
  session: null,
  recoveryReady: false,
  loading: false,
  error: "Privy authentication is not configured.",
  client: null,
  login: () => undefined,
  selectOrganization: () => undefined,
  createWorkspace: async () => { throw new Error("Privy authentication is not configured."); },
  unlockWorkspace: async () => { throw new Error("Privy authentication is not configured."); },
  importRecoveryPackage: () => { throw new Error("Privy authentication is not configured."); },
  downloadRecoveryPackage: () => { throw new Error("Privy authentication is not configured."); },
  confirmRecoverySaved: async () => { throw new Error("Privy authentication is not configured."); },
  createSecondAdminRequest: async () => { throw new Error("Privy authentication is not configured."); },
  addSecondAdministrator: async () => { throw new Error("Privy authentication is not configured."); },
  rotateVault: async () => { throw new Error("Privy authentication is not configured."); },
  lockWorkspace: () => undefined,
  refreshOrganizations: async () => undefined,
};

export const PayoVaultContext = createContext<PayoVaultContextValue>(unavailableValue);

function recoveryStorageKey(organizationId: string): string {
  return `payo:vault-recovery:v1:${organizationId}`;
}

function enrollmentStorageKey(organizationId: string): string {
  return `payo:vault-enrollment:v1:${organizationId}`;
}

function saveRecoveryPackage(pkg: VaultRecoveryPackage): void {
  localStorage.setItem(recoveryStorageKey(pkg.organizationId), JSON.stringify(pkg));
}

function readRecoveryPackage(organizationId: string): VaultRecoveryPackage {
  const serialized = localStorage.getItem(recoveryStorageKey(organizationId));
  if (!serialized) {
    throw new Error("This browser has no recovery package. Import the downloaded package to continue.");
  }
  return vaultRecoveryPackageSchema.parse(JSON.parse(serialized));
}

function readEnrollmentPackage(organizationId: string): VaultSecondAdminEnrollment | null {
  const serialized = localStorage.getItem(enrollmentStorageKey(organizationId));
  return serialized ? vaultSecondAdminEnrollmentSchema.parse(JSON.parse(serialized)) : null;
}

function downloadPackage(pkg: VaultRecoveryPackage): void {
  const blob = new Blob([`${JSON.stringify(pkg, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `payo-recovery-${pkg.organizationId}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function downloadEnrollment(pkg: VaultSecondAdminEnrollment): void {
  const blob = new Blob([`${JSON.stringify(pkg, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `payo-second-admin-${pkg.organizationId}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function PayoVaultUnavailableProvider({ children }: { children: ReactNode }) {
  return <PayoVaultContext.Provider value={unavailableValue}>{children}</PayoVaultContext.Provider>;
}

export function PayoVaultProvider({ children }: { children: ReactNode }) {
  const { ready, authenticated, user, getAccessToken } = usePrivy();
  const { login } = useLogin();
  const principalId = user?.id ?? "";
  const client = useMemo(() => new PayoClient(getAccessToken), [getAccessToken]);
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState("");
  const [session, setSession] = useState<VaultSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const refreshOrganizations = useCallback(async () => {
    if (!authenticated) {
      setOrganizations([]);
      return;
    }
    const result = await client.listOrganizations();
    const summaries = result.organizations.map((organization) => ({
      id: organization.id,
      recoveryState: organization.recoveryState,
      keyVersion: organization.keyVersion,
      role: organization.role,
      encryptedProfile: organization.encryptedProfile,
      vaultPublicKey: organization.vaultPublicKey,
      createdAt: organization.createdAt,
    }));
    setOrganizations(summaries);
    setSelectedOrganizationId((current) => current || summaries[0]?.id || "");
  }, [authenticated, client]);

  useEffect(() => {
    const synchronizationTimer = window.setTimeout(() => {
      if (!ready || !authenticated) {
        if (ready) {
          setOrganizations([]);
          setSelectedOrganizationId("");
          setSession(null);
          setLoading(false);
        }
        return;
      }
      setLoading(true);
      setError("");
      void refreshOrganizations()
        .catch((organizationError) => setError(
          organizationError instanceof Error ? organizationError.message : "Private workspace loading failed.",
        ))
        .finally(() => setLoading(false));
    }, 0);
    return () => window.clearTimeout(synchronizationTimer);
  }, [authenticated, ready, refreshOrganizations]);

  const selectOrganization = useCallback((organizationId: string) => {
    setSelectedOrganizationId(organizationId);
    setSession((current) => current?.organizationId === organizationId ? current : null);
    setError("");
  }, []);

  const createWorkspace = useCallback(async (organizationName: string, recoveryPassword: string) => {
    if (!authenticated || !principalId) throw new Error("Sign in before creating a PAYO workspace.");
    setLoading(true);
    setError("");
    try {
      const workspace = await createVaultWorkspace({ principalId, organizationName, recoveryPassword });
      await client.createOrganization({
        organizationId: workspace.organizationId,
        encryptedProfile: workspace.encryptedProfile,
        vaultPublicKey: workspace.principal.publicKey,
        initialPrincipal: workspace.initialPrincipal,
      });
      saveRecoveryPackage(workspace.recoveryPackage);
      downloadPackage(workspace.recoveryPackage);
      setSelectedOrganizationId(workspace.organizationId);
      setSession({
        organizationId: workspace.organizationId,
        organizationSecret: workspace.organizationSecret,
        principal: workspace.principal,
      });
      await refreshOrganizations();
    } catch (workspaceError) {
      const message = workspaceError instanceof Error ? workspaceError.message : "Workspace creation failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, principalId, refreshOrganizations]);

  const unlockWorkspace = useCallback(async (password: string) => {
    if (!selectedOrganizationId) throw new Error("Select a PAYO organization first.");
    setLoading(true);
    setError("");
    try {
      let unlocked;
      try {
        unlocked = await unlockVaultWorkspace(readRecoveryPackage(selectedOrganizationId), password);
      } catch (recoveryError) {
        const enrollment = readEnrollmentPackage(selectedOrganizationId);
        if (!enrollment) throw recoveryError;
        const recovered = await finishSecondAdminRecovery({ client, enrollment, password });
        saveRecoveryPackage(recovered.recoveryPackage);
        localStorage.removeItem(enrollmentStorageKey(selectedOrganizationId));
        unlocked = recovered;
      }
      if (unlocked.principal.principalId !== principalId) {
        throw new Error("This recovery package belongs to a different authenticated principal.");
      }
      setSession(unlocked);
    } catch (unlockError) {
      const message = unlockError instanceof Error ? unlockError.message : "Vault unlock failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, [client, principalId, selectedOrganizationId]);

  const importRecoveryPackage = useCallback((packageInput: unknown) => {
    const enrollment = vaultSecondAdminEnrollmentSchema.safeParse(packageInput);
    if (enrollment.success) {
      if (enrollment.data.principalId !== principalId) {
        throw new Error("This second-admin package belongs to another authenticated principal.");
      }
      localStorage.setItem(enrollmentStorageKey(enrollment.data.organizationId), JSON.stringify(enrollment.data));
      setSelectedOrganizationId(enrollment.data.organizationId);
      setSession(null);
      setError("");
      return;
    }
    const pkg = vaultRecoveryPackageSchema.parse(packageInput);
    if (!organizations.some(({ id }) => id === pkg.organizationId)) {
      throw new Error("This recovery package does not belong to an organization available to this account.");
    }
    saveRecoveryPackage(pkg);
    setSelectedOrganizationId(pkg.organizationId);
    setSession(null);
    setError("");
  }, [organizations, principalId]);

  const createSecondAdminRequest = useCallback(async (organizationId: string, password: string) => {
    if (!authenticated || !principalId) throw new Error("Sign in before creating a recovery-admin request.");
    const enrollment = await createSecondAdminEnrollment({
      organizationId: organizationId.trim(),
      principalId,
      password,
    });
    localStorage.setItem(enrollmentStorageKey(enrollment.organizationId), JSON.stringify(enrollment));
    downloadEnrollment(enrollment);
  }, [authenticated, principalId]);

  const addSecondAdministrator = useCallback(async (enrollmentInput: unknown) => {
    if (!session) throw new Error("Unlock the organization before adding a recovery administrator.");
    const enrollment = vaultSecondAdminEnrollmentSchema.parse(enrollmentInput);
    const organization = organizations.find(({ id }) => id === session.organizationId);
    if (!organization || organization.role !== "admin") {
      throw new Error("Only an organization administrator can add a recovery administrator.");
    }
    const grant = prepareSecondAdminGrant({
      organizationId: session.organizationId,
      organizationSecret: session.organizationSecret,
      authorizingPrincipal: session.principal,
      encryptedProfile: organization.encryptedProfile,
      enrollment,
      keyVersion: organization.keyVersion,
    });
    await client.addSecondAdministrator({ organizationId: session.organizationId, ...grant });
    await refreshOrganizations();
  }, [client, organizations, refreshOrganizations, session]);

  const downloadRecoveryPackage = useCallback(() => {
    if (!selectedOrganizationId) throw new Error("Select a PAYO organization first.");
    downloadPackage(readRecoveryPackage(selectedOrganizationId));
  }, [selectedOrganizationId]);

  const confirmRecoverySaved = useCallback(async () => {
    if (!selectedOrganizationId) throw new Error("Select a PAYO organization first.");
    setLoading(true);
    setError("");
    try {
      const pkg = readRecoveryPackage(selectedOrganizationId);
      await client.acknowledgeRecoveryPackage(selectedOrganizationId, hashCanonicalJson(pkg));
      await refreshOrganizations();
    } catch (confirmationError) {
      const message = confirmationError instanceof Error
        ? confirmationError.message
        : "Recovery confirmation failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, [client, refreshOrganizations, selectedOrganizationId]);

  const rotateVault = useCallback(async (
    newRecoveryPassword: string,
    revokePrincipalIds: readonly string[] = [],
  ) => {
    if (!session) throw new Error("Unlock the organization before rotating vault keys.");
    const organization = organizations.find(({ id }) => id === session.organizationId);
    if (!organization || organization.role !== "admin") {
      throw new Error("Only an organization administrator can rotate vault keys.");
    }
    setLoading(true);
    setError("");
    try {
      const rotated = await rotateClientVault({
        client,
        organizationId: session.organizationId,
        currentPrincipal: session.principal,
        currentEncryptedProfile: organization.encryptedProfile,
        newRecoveryPassword,
        revokePrincipalIds,
      });
      saveRecoveryPackage(rotated.recoveryPackage);
      downloadPackage(rotated.recoveryPackage);
      setSession({
        organizationId: rotated.organizationId,
        organizationSecret: rotated.organizationSecret,
        principal: rotated.principal,
      });
      await refreshOrganizations();
    } catch (rotationError) {
      const message = rotationError instanceof Error ? rotationError.message : "Vault-key rotation failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, [client, organizations, refreshOrganizations, session]);

  const selectedOrganization = organizations.find(({ id }) => id === selectedOrganizationId);
  const recoveryReady = selectedOrganization?.recoveryState !== "required";

  const value = useMemo<PayoVaultContextValue>(() => ({
    configured: true,
    ready,
    authenticated,
    principalId,
    organizations,
    selectedOrganizationId,
    session,
    recoveryReady,
    loading,
    error,
    client,
    login,
    selectOrganization,
    createWorkspace,
    unlockWorkspace,
    importRecoveryPackage,
    downloadRecoveryPackage,
    confirmRecoverySaved,
    createSecondAdminRequest,
    addSecondAdministrator,
    rotateVault,
    lockWorkspace: () => setSession(null),
    refreshOrganizations,
  }), [
    authenticated,
    client,
    createWorkspace,
    confirmRecoverySaved,
    createSecondAdminRequest,
    addSecondAdministrator,
    rotateVault,
    downloadRecoveryPackage,
    error,
    loading,
    login,
    organizations,
    principalId,
    ready,
    refreshOrganizations,
    importRecoveryPackage,
    recoveryReady,
    selectOrganization,
    selectedOrganizationId,
    session,
    unlockWorkspace,
  ]);

  return <PayoVaultContext.Provider value={value}>{children}</PayoVaultContext.Provider>;
}

export function usePayoVault() {
  return useContext(PayoVaultContext);
}
