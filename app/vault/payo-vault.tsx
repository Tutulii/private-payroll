"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { PayoApiError, PayoClient } from "@/lib/client/payo-client";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  createVaultWorkspace,
  unlockVaultWorkspace,
} from "@/lib/client/vault-workspace";
import {
  vaultRecoveryPackageSchema,
  vaultSecondAdminEnrollmentSchema,
  decryptVaultRecord,
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
import {
  readySessionPayloadSchema,
  type ReadySessionPayload,
} from "@/lib/auth/ready-session";
import { useStarknetWallet } from "@/app/starknet/starknet-wallet";

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
  sessionExpiresAt: string;
  login: () => Promise<void>;
  logout: () => Promise<void>;
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
  error: "Ready wallet authentication is not available.",
  client: null,
  sessionExpiresAt: "",
  login: async () => { throw new Error("Ready wallet authentication is not available."); },
  logout: async () => undefined,
  selectOrganization: () => undefined,
  createWorkspace: async () => { throw new Error("Ready wallet authentication is not available."); },
  unlockWorkspace: async () => { throw new Error("Ready wallet authentication is not available."); },
  importRecoveryPackage: () => { throw new Error("Ready wallet authentication is not available."); },
  downloadRecoveryPackage: () => { throw new Error("Ready wallet authentication is not available."); },
  confirmRecoverySaved: async () => { throw new Error("Ready wallet authentication is not available."); },
  createSecondAdminRequest: async () => { throw new Error("Ready wallet authentication is not available."); },
  addSecondAdministrator: async () => { throw new Error("Ready wallet authentication is not available."); },
  rotateVault: async () => { throw new Error("Ready wallet authentication is not available."); },
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

function readySessionStorageKey(walletAddress: string): string {
  return `payo:ready-session:v1:${walletAddress.toLowerCase()}`;
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

function firstStoredRecoveryOrganizationId(): string {
  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (!key?.startsWith("payo:vault-recovery:v1:")) continue;
    const serialized = localStorage.getItem(key);
    if (!serialized) continue;
    try {
      const pkg = vaultRecoveryPackageSchema.parse(JSON.parse(serialized));
      if (key === recoveryStorageKey(pkg.organizationId)) return pkg.organizationId;
    } catch {
      // Ignore unrelated or corrupt local-storage entries; explicit import still reports errors.
    }
  }
  return "";
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
  const starknet = useStarknetWallet();
  const [authSession, setAuthSession] = useState<ReadySessionPayload | null>(null);
  const accessToken = authSession?.accessToken ?? null;
  const client = useMemo(() => new PayoClient(async () => accessToken), [accessToken]);
  const ready = starknet.discoveryReady;
  const authenticated = Boolean(
    authSession
    && starknet.isConnected
    && starknet.isMainnet
    && authSession.walletAddress.toLowerCase() === starknet.address.toLowerCase(),
  );
  const principalId = authenticated ? authSession?.principalId ?? "" : "";
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState("");
  const [session, setSession] = useState<VaultSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const applyReadySession = useCallback((nextSession: ReadySessionPayload) => {
    const parsed = readySessionPayloadSchema.parse(nextSession);
    setAuthSession(parsed);
    localStorage.setItem(readySessionStorageKey(parsed.walletAddress), JSON.stringify(parsed));
  }, []);

  const clearReadySession = useCallback((removeStored = false) => {
    if (removeStored && authSession?.walletAddress) {
      localStorage.removeItem(readySessionStorageKey(authSession.walletAddress));
    }
    setAuthSession(null);
    setOrganizations([]);
    setSelectedOrganizationId("");
    setSession(null);
  }, [authSession]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!starknet.isConnected || !starknet.isMainnet || !starknet.address) {
        setAuthSession(null);
        setOrganizations([]);
        setSelectedOrganizationId("");
        setSession(null);
        return;
      }
      const storageKey = readySessionStorageKey(starknet.address);
      const serialized = localStorage.getItem(storageKey);
      if (!serialized) {
        setAuthSession(null);
        return;
      }
      let parsed;
      try {
        parsed = readySessionPayloadSchema.safeParse(JSON.parse(serialized));
      } catch {
        localStorage.removeItem(storageKey);
        setAuthSession(null);
        return;
      }
      if (
        !parsed.success
        || parsed.data.walletAddress.toLowerCase() !== starknet.address.toLowerCase()
        || new Date(parsed.data.expiresAt).getTime() <= Date.now()
      ) {
        localStorage.removeItem(storageKey);
        setAuthSession(null);
        return;
      }
      setAuthSession(parsed.data);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [starknet.address, starknet.isConnected, starknet.isMainnet]);

  useEffect(() => {
    if (!authSession) return;
    const remaining = new Date(authSession.expiresAt).getTime() - Date.now();
    const timer = window.setTimeout(
      () => clearReadySession(true),
      Math.max(0, Math.min(remaining, 2_147_000_000)),
    );
    return () => window.clearTimeout(timer);
  }, [authSession, clearReadySession]);

  const login = useCallback(async () => {
    if (!starknet.isConnected) throw new Error("Connect Ready wallet before authorizing PAYO.");
    if (!starknet.isMainnet) throw new Error("Switch Ready to Starknet Mainnet first.");
    setLoading(true);
    setError("");
    try {
      const { challenge } = await client.createReadyAuthenticationChallenge({
        walletAddress: starknet.address,
        chainId: starknet.chainId,
      });
      const signature = await starknet.signPayoSession(challenge.typedData);
      const { session: nextSession } = await client.verifyReadyAuthentication({
        challengeId: challenge.challengeId,
        signature,
      });
      applyReadySession(nextSession);
    } catch (authenticationError) {
      const message = authenticationError instanceof Error
        ? authenticationError.message
        : "Ready authentication failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, [applyReadySession, client, starknet]);

  const logout = useCallback(async () => {
    try {
      await client.revokeReadyAuthentication();
    } finally {
      clearReadySession(true);
    }
  }, [clearReadySession, client]);

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
    setSelectedOrganizationId((current) =>
      current || summaries[0]?.id || firstStoredRecoveryOrganizationId());
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
        .catch((organizationError) => {
          const message = organizationError instanceof Error
            ? organizationError.message
            : "Private workspace loading failed.";
          setError(message);
          if (organizationError instanceof PayoApiError && organizationError.code === "AUTH_INVALID") {
            clearReadySession(true);
          }
        })
        .finally(() => setLoading(false));
    }, 0);
    return () => window.clearTimeout(synchronizationTimer);
  }, [authenticated, clearReadySession, ready, refreshOrganizations]);

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
        const { recoveryLink } = await client.createReadyRecoveryLink({
          organizationId: selectedOrganizationId,
          legacyPrincipalId: unlocked.principal.principalId,
        });
        const recoveredChallenge = decryptVaultRecord<{ proof: string }>(
          recoveryLink.envelope,
          unlocked.principal,
        );
        const { session: linkedSession } = await client.completeReadyRecoveryLink({
          challengeId: recoveryLink.challengeId,
          proof: recoveredChallenge.proof,
        });
        if (linkedSession.principalId !== unlocked.principal.principalId) {
          throw new Error("Ready linked an unexpected PAYO principal.");
        }
        applyReadySession(linkedSession);
      }
      setSession(unlocked);
    } catch (unlockError) {
      const message = unlockError instanceof Error ? unlockError.message : "Vault unlock failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, [applyReadySession, client, principalId, selectedOrganizationId]);

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
    saveRecoveryPackage(pkg);
    setSelectedOrganizationId(pkg.organizationId);
    setSession(null);
    setError("");
  }, [principalId]);

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
  const recoveryReady = Boolean(selectedOrganization && selectedOrganization.recoveryState !== "required");

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
    sessionExpiresAt: authSession?.expiresAt ?? "",
    login,
    logout,
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
    authSession?.expiresAt,
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
    logout,
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
