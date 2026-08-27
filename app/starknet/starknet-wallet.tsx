"use client";

import { createStore, type Store } from "@starknet-io/get-starknet-discovery";
import type { WalletWithStarknetFeatures } from "@starknet-io/get-starknet-wallet-standard/features";
import {
  constants as starknetConstants,
  hash,
  num,
  RpcProvider,
  uint256,
  validateAndParseAddress,
  WalletAccountV6,
  walletV6,
  type STRK20_ACTION,
  type STRK20_INVOKE_ACTION,
  type TypedData,
} from "starknet";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  emptyTokenBalances,
  assertPrivacyTokenEnabled,
  formatTokenAmount,
  parseTokenAmount,
  PAYROLL_TOKEN_LIST,
  PAYROLL_TOKENS,
  PRIVACY_PAYROLL_TOKEN_LIST,
  type PayrollTokenSymbol,
  type TokenBalanceMap,
} from "./tokens";
import {
  STARKNET_MAINNET_CHAIN_ID,
  STRK20_MAINNET_POOL_ADDRESS,
} from "@/lib/starknet/deployment";
import {
  buildPrivateExceptionActions,
  buildPrivatePayrollActions,
  requiredPayrollReservesForQuotes,
  type PrivateExceptionWorkflow,
} from "@/lib/starknet/private-payroll";
import { describeWalletError } from "@/lib/starknet/wallet-error";
import {
  prepareFxRootPublication,
  preparePayoBaselineSchedule,
  preparePayoPhase3VerifierSchedule,
  prepareObligationRootSchedule,
  rootLimbs,
} from "@/lib/starknet/payo-registry";
import { PAYO_PHASE3_MAINNET_DEPLOYMENT } from "@/lib/starknet/payo-phase3-deployment";
import {
  buildPayoMainnetTopologyPlan,
  PAYO_DEPLOYMENT_ARTIFACT_NAMES,
  type PayoBrowserDeploymentPackage,
  type PayoDeploymentArtifactName,
  type PayoMainnetTopologyPlan,
} from "@/lib/starknet/payo-deployment-plan";

export {
  formatTokenAmount,
  parseTokenAmount,
  PAYROLL_TOKEN_LIST,
  PAYROLL_TOKENS,
  PRIVACY_PAYROLL_TOKEN_LIST,
  STRK_TOKEN_ADDRESS,
  USDC_TOKEN_ADDRESS,
  type PayrollTokenSymbol,
} from "./tokens";

export const STRK20_SETUP_URL = "https://strk20.starknet.io/app";
export const STARKNET_MAINNET_EXPLORER = "https://starkscan.co";

export { STARKNET_MAINNET_CHAIN_ID, STRK20_MAINNET_POOL_ADDRESS };

const starknetRpcUrl =
  process.env.NEXT_PUBLIC_STARKNET_RPC_URL ?? "https://rpc.starknet.lava.build";
const mainnetProvider = new RpcProvider({ nodeUrl: starknetRpcUrl });

export type PayrollRecipient = {
  address: string;
  amount: string;
  token: PayrollTokenSymbol;
};

export type WalletChoice = {
  name: string;
  icon: string;
  privacyReady: boolean;
};

export type PrivateTransaction = {
  kind: "shield" | "payroll" | "wage_claim" | "wage_remediation" | "registry" | "deployment";
  stage: "wallet" | "confirming" | "confirmed" | "failed";
  label: string;
  hash?: string;
  error?: string;
  grossAmount?: bigint;
  walletFee?: bigint;
  feeToken?: PayrollTokenSymbol;
  netAmount?: bigint;
  balanceRefreshed?: boolean;
  balanceRefreshError?: string;
  token?: PayrollTokenSymbol;
  totals?: Partial<Record<PayrollTokenSymbol, bigint>>;
  feeReserves?: Partial<Record<PayrollTokenSymbol, bigint>>;
  feeQuoteExact?: boolean;
  shieldedBalanceBefore?: bigint;
};

export type ObligationRootScheduleResult = {
  transactionHash: string;
  validAfter: number;
  expiresAt: number;
};

export type ShieldFeeQuote = {
  token: PayrollTokenSymbol;
  grossAmount: bigint;
  walletFee: bigint;
  netAmount: bigint;
  source: "pool-onchain" | "paymaster-live-estimate";
  exact: boolean;
  quotedAt: number;
};

type PrivateFeeQuote = Pick<
  ShieldFeeQuote,
  "token" | "walletFee" | "source" | "exact" | "quotedAt"
>;

export type PayoDeploymentProgress = {
  stage: "checking" | "declaring" | "deploying" | "verifying";
  message: string;
  contract?: PayoDeploymentArtifactName;
  transactionHash?: string;
};

export type PayoMainnetDeploymentResult = {
  plan: PayoMainnetTopologyPlan;
  declarationTransactionHashes: Partial<Record<PayoDeploymentArtifactName, string>>;
  deploymentTransactionHash: string | null;
  verifiedBlockNumber: number;
};

export type PayoBaselineScheduleResult = {
  transactionHash: string;
  policyRoot: string;
  validAfter: number;
  expiresAt: number;
};

export type PayoPhase3ActivationStatus = {
  blockNumber: number;
  topologyReady: boolean;
  walletIsAdmin: boolean;
  allActive: boolean;
  profiles: Array<{
    name: string;
    mode: number;
    proofVersion: number;
    bundleAddress: string;
    active: boolean;
  }>;
};

export type PayoPhase3ActivationResult = {
  transactionHash: string;
  validAfter: number;
  expiresAt: number;
  status: PayoPhase3ActivationStatus;
};

export type PrivacyCapability =
  | "unknown"
  | "checking"
  | "uninitialized"
  | "zero"
  | "available"
  | "error"
  | "unsupported";

type StarknetWalletContextValue = {
  wallets: WalletChoice[];
  discoveryReady: boolean;
  isConnected: boolean;
  isConnecting: boolean;
  walletName: string;
  address: string;
  chainId: string;
  networkName: string;
  isMainnet: boolean;
  supportedSpecs: string[];
  walletApiVersions: string[];
  walletApiVersion: string;
  privacyCapability: PrivacyCapability;
  privacyMessage: string;
  shieldedBalances: TokenBalanceMap;
  publicBalances: TokenBalanceMap;
  shieldedBalance: bigint | null;
  publicStrkBalance: bigint | null;
  isRefreshingPublicBalance: boolean;
  publicBalanceError: string;
  isRefreshingBalance: boolean;
  transaction: PrivateTransaction | null;
  error: string;
  connectWallet: (name: string) => Promise<void>;
  disconnectWallet: () => Promise<void>;
  signPayoSession: (typedData: TypedData) => Promise<string[]>;
  switchToMainnet: () => Promise<void>;
  refreshPublicBalance: () => Promise<bigint>;
  refreshBalance: () => Promise<void>;
  quoteShieldToken: (token: PayrollTokenSymbol, amount: string) => Promise<ShieldFeeQuote>;
  shieldToken: (token: PayrollTokenSymbol, amount: string, quote?: ShieldFeeQuote) => Promise<string>;
  shieldStrk: (amount: string) => Promise<string>;
  runProofBoundPayroll: (
    recipients: PayrollRecipient[],
    payoAction: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  runProofBoundException: (
    workflow: PrivateExceptionWorkflow,
    recipients: PayrollRecipient[],
    payoAction: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  reconcilePayrollTransaction: (transactionHash: string) => Promise<void>;
  scheduleObligationRoot: (agreementRoot: string) => Promise<ObligationRootScheduleResult>;
  isObligationRootActive: (agreementRoot: string) => Promise<boolean>;
  getObligationRootOwner: (agreementRoot: string) => Promise<string>;
  publishFxRoot: (input: {
    root: string;
    observedAt: number;
    maximumAgeSeconds: number;
  }) => Promise<string>;
  isFxRootActive: (fxRoot: string) => Promise<boolean>;
  deployPayoMainnet: (
    deploymentPackage: PayoBrowserDeploymentPackage,
    onProgress?: (progress: PayoDeploymentProgress) => void,
  ) => Promise<PayoMainnetDeploymentResult>;
  schedulePayoBaseline: (
    plan: PayoMainnetTopologyPlan,
    policyRoot: string,
  ) => Promise<PayoBaselineScheduleResult>;
  readPayoPhase3Activation: () => Promise<PayoPhase3ActivationStatus>;
  activatePayoPhase3: () => Promise<PayoPhase3ActivationResult>;
  clearTransaction: () => void;
};

const StarknetWalletContext = createContext<StarknetWalletContextValue | null>(null);

function normalizeWalletName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isReadyWallet(name: string) {
  const normalized = normalizeWalletName(name);
  return normalized.includes("ready") || normalized.includes("argentx");
}

function describeError(error: unknown) {
  return describeWalletError(error);
}

function missingStarknetClass(error: unknown): boolean {
  return /class hash not found|undeclared class|class_hash_not_found/i.test(describeError(error));
}

function missingStarknetContract(error: unknown): boolean {
  return /contract not found|contract_address_not_found|uninitialized contract/i.test(
    describeError(error),
  );
}

function walletErrorCode(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  const candidate = error as {
    code?: unknown;
    error?: { code?: unknown };
  };
  const code = candidate.code ?? candidate.error?.code;
  return typeof code === "string" || typeof code === "number" ? String(code) : "";
}

function errorIncludes(error: unknown, value: string) {
  return describeError(error).toUpperCase().includes(value);
}

function isNotRegisteredError(error: unknown) {
  return walletErrorCode(error) === "118" || errorIncludes(error, "NOT_REGISTERED");
}

function isUnsupportedWalletApiError(error: unknown) {
  const code = walletErrorCode(error);
  return (
    code === "162" ||
    code === "-32601" ||
    code === "4200" ||
    errorIncludes(error, "API_VERSION_NOT_SUPPORTED") ||
    errorIncludes(error, "METHOD_NOT_FOUND") ||
    errorIncludes(error, "METHOD NOT FOUND") ||
    errorIncludes(error, "UNSUPPORTED METHOD")
  );
}

async function readMainnetPoolRegistration(address: string): Promise<boolean | null> {
  try {
    const result = await mainnetProvider.callContract({
      contractAddress: STRK20_MAINNET_POOL_ADDRESS,
      entrypoint: "get_public_key",
      calldata: [address],
    });
    return num.toBigInt(result[0] ?? "0x0") !== 0n;
  } catch {
    return null;
  }
}

async function readMainnetPublicTokenBalance(
  tokenAddress: string,
  address: string,
): Promise<bigint> {
  const result = await mainnetProvider.callContract({
    contractAddress: tokenAddress,
    entrypoint: "balance_of",
    calldata: [address],
  });
  return uint256.uint256ToBN({
    low: result[0] ?? "0x0",
    high: result[1] ?? "0x0",
  });
}

function versionParts(version: string) {
  return version
    .split("-")[0]
    .split(".")
    .map((part) => Number.parseInt(part, 10) || 0);
}

function compareVersions(left: string, right: string) {
  const leftParts = versionParts(left);
  const rightParts = versionParts(right);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function supportsStrk20WalletApi(versions: string[]) {
  return versions.some((version) => compareVersions(version, "0.10.3") >= 0);
}

function latestVersion(versions: string[]) {
  return [...versions].sort(compareVersions).at(-1) ?? "";
}

export function parseStrkAmount(value: string): bigint {
  return parseTokenAmount(value, "STRK");
}

export function formatStrk(amount: bigint | null, maximumFractionDigits = 6) {
  return formatTokenAmount(amount, "STRK", maximumFractionDigits);
}

export function shortStarknetAddress(address: string) {
  if (!address) return "Not connected";
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

export function StarknetWalletProvider({ children }: { children: ReactNode }) {
  const [discoveredWallets, setDiscoveredWallets] = useState<WalletWithStarknetFeatures[]>([]);
  const [discoveryReady, setDiscoveryReady] = useState(false);
  const [walletAccount, setWalletAccount] = useState<WalletAccountV6 | null>(null);
  const [selectedWallet, setSelectedWallet] = useState<WalletWithStarknetFeatures | null>(null);
  const [address, setAddress] = useState("");
  const [chainId, setChainId] = useState("");
  const [supportedSpecs, setSupportedSpecs] = useState<string[]>([]);
  const [walletApiVersions, setWalletApiVersions] = useState<string[]>([]);
  const [isConnecting, setIsConnecting] = useState(false);
  const [shieldedBalance, setShieldedBalance] = useState<bigint | null>(null);
  const [publicStrkBalance, setPublicStrkBalance] = useState<bigint | null>(null);
  const [shieldedBalances, setShieldedBalances] = useState<TokenBalanceMap>(emptyTokenBalances);
  const [publicBalances, setPublicBalances] = useState<TokenBalanceMap>(emptyTokenBalances);
  const [isRefreshingPublicBalance, setIsRefreshingPublicBalance] = useState(false);
  const [publicBalanceError, setPublicBalanceError] = useState("");
  const [isRefreshingBalance, setIsRefreshingBalance] = useState(false);
  const [privacyCapability, setPrivacyCapability] = useState<PrivacyCapability>("unknown");
  const [privacyMessage, setPrivacyMessage] = useState("");
  const [transaction, setTransaction] = useState<PrivateTransaction | null>(null);
  const [error, setError] = useState("");
  const unsubscribeWalletRef = useRef<(() => void) | null>(null);
  const privateActionLockRef = useRef<symbol | null>(null);

  useEffect(() => {
    const store: Store = createStore({ eip1193Adapters: [] });
    const updateWallets = (wallets: readonly WalletWithStarknetFeatures[]) => {
      setDiscoveredWallets(
        wallets.filter((wallet) => !normalizeWalletName(wallet.name).includes("metamask")),
      );
      setDiscoveryReady(true);
    };

    updateWallets(store.getWallets());
    const unsubscribe = store.subscribe(updateWallets);
    return unsubscribe;
  }, []);

  const refreshPublicBalanceForAddress = useCallback(async (walletAddress: string) => {
    setIsRefreshingPublicBalance(true);
    setPublicBalanceError("");
    try {
      const entries = await Promise.all(
        PAYROLL_TOKEN_LIST.map(async (token) => {
          const balance = await readMainnetPublicTokenBalance(token.address, walletAddress);
          return [token.symbol, balance] as const;
        }),
      );
      const balances = Object.fromEntries(entries) as Record<PayrollTokenSymbol, bigint>;
      setPublicBalances(balances);
      setPublicStrkBalance(balances.STRK);
      return balances;
    } catch (balanceError) {
      const message = describeError(balanceError);
      setPublicStrkBalance(null);
      setPublicBalances(emptyTokenBalances());
      setPublicBalanceError(message);
      throw new Error(message);
    } finally {
      setIsRefreshingPublicBalance(false);
    }
  }, []);

  const clearConnection = useCallback(() => {
    unsubscribeWalletRef.current?.();
    unsubscribeWalletRef.current = null;
    setWalletAccount(null);
    setSelectedWallet(null);
    setAddress("");
    setChainId("");
    setSupportedSpecs([]);
    setWalletApiVersions([]);
    setShieldedBalance(null);
    setShieldedBalances(emptyTokenBalances());
    setPublicStrkBalance(null);
    setPublicBalances(emptyTokenBalances());
    setPublicBalanceError("");
    setPrivacyCapability("unknown");
    setPrivacyMessage("");
    setTransaction(null);
    privateActionLockRef.current = null;
  }, []);

  const refreshPublicBalance = useCallback(async () => {
    if (!address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
      throw new Error("Switch Ready to Starknet Mainnet first.");
    }
    const balances = await refreshPublicBalanceForAddress(address);
    return balances.STRK;
  }, [address, chainId, refreshPublicBalanceForAddress]);

  useEffect(() => {
    if (!address || chainId !== STARKNET_MAINNET_CHAIN_ID) return;
    const interval = window.setInterval(() => {
      void refreshPublicBalanceForAddress(address).catch(() => undefined);
    }, 30_000);
    return () => window.clearInterval(interval);
  }, [address, chainId, refreshPublicBalanceForAddress]);

  const refreshBalanceForAccount = useCallback(async (account: WalletAccountV6) => {
    setIsRefreshingBalance(true);
    setPrivacyCapability("checking");
    setPrivacyMessage("");
    try {
      const balances = await account.strk20Balances(PRIVACY_PAYROLL_TOKEN_LIST.map((token) => token.address));
      const nextBalances = PRIVACY_PAYROLL_TOKEN_LIST.reduce<Record<PayrollTokenSymbol, bigint>>(
        (result, token) => {
          const entry = balances.find((candidate) => {
            try {
              return num.toBigInt(candidate.token) === num.toBigInt(token.address);
            } catch {
              return false;
            }
          });
          result[token.symbol] = entry ? num.toBigInt(entry.balance) : 0n;
          return result;
        },
        { STRK: 0n, USDC: 0n },
      );
      const hasPrivateFunds = Object.values(nextBalances).some((balance) => balance > 0n);
      setShieldedBalances(nextBalances);
      setShieldedBalance(nextBalances.STRK);
      setPrivacyCapability(hasPrivateFunds ? "available" : "zero");
      setPrivacyMessage(
        hasPrivateFunds
          ? "Your enabled private treasury balances are available for payroll."
          : "Your STRK20 account is ready but its private payroll balances are zero.",
      );
      return nextBalances;
    } catch (balanceError) {
      const message = describeError(balanceError);
      setShieldedBalance(null);
      setShieldedBalances(emptyTokenBalances());
      const poolRegistration = isNotRegisteredError(balanceError)
        ? false
        : await readMainnetPoolRegistration(account.address);
      if (poolRegistration === false) {
        setPrivacyCapability("uninitialized");
        setPrivacyMessage(
          "This account is not registered in the STRK20 pool. Ready Wallet API 0.10.3 cannot register it from a dapp; complete the one-time STRK20 setup, then refresh.",
        );
        throw new Error("STRK20 registration is required before shielding.");
      }
      if (isUnsupportedWalletApiError(balanceError)) {
        setPrivacyCapability("unsupported");
        setPrivacyMessage(
          `Ready rejected the STRK20 balance method. Update Ready and reconnect. Wallet response: ${message}`,
        );
        throw new Error("This Ready version does not support the STRK20 balance API.");
      }
      setPrivacyCapability("error");
      setPrivacyMessage(`Ready could not read the private STRK balance: ${message}`);
      throw new Error(`Private STRK balance check failed: ${message}`);
    } finally {
      setIsRefreshingBalance(false);
    }
  }, []);

  const refreshBalance = useCallback(async () => {
    if (!walletAccount) throw new Error("Connect Ready wallet first.");
    if (privacyCapability === "unsupported") {
      throw new Error("This Ready version does not support the STRK20 Wallet API.");
    }
    await refreshBalanceForAccount(walletAccount);
  }, [privacyCapability, refreshBalanceForAccount, walletAccount]);

  const connectWallet = useCallback(
    async (name: string) => {
      const wallet = discoveredWallets.find((candidate) => candidate.name === name);
      if (!wallet) throw new Error("That wallet is no longer available. Reopen the picker.");

      setError("");
      setIsConnecting(true);
      setTransaction(null);
      try {
        const account = await WalletAccountV6.connect(mainnetProvider, wallet);
        const accounts = await walletV6.requestAccounts(wallet);
        if (!Array.isArray(accounts) || !accounts[0]) {
          throw new Error("This wallet did not return a Starknet account.");
        }

        const permissions = await walletV6.getPermissions(wallet);
        if (!permissions.includes("accounts")) {
          throw new Error("Account access was not approved in the wallet.");
        }

        const connectedAddress = validateAndParseAddress(accounts[0]);
        const activeChainId = String(await walletV6.requestChainId(wallet));
        const [specsResult, walletApiResult] = await Promise.allSettled([
          walletV6.supportedSpecs(wallet),
          walletV6.supportedWalletApi(wallet),
        ]);
        const specs = specsResult.status === "fulfilled" ? specsResult.value.map(String) : [];
        const apiVersions =
          walletApiResult.status === "fulfilled" ? walletApiResult.value.map(String) : [];

        unsubscribeWalletRef.current?.();
        unsubscribeWalletRef.current = account.onChange((change) => {
          let balanceAddress = account.address;
          if (change.accounts) {
            const nextAddress = change.accounts[0]?.address;
            if (!nextAddress) {
              clearConnection();
              return;
            }
            try {
              balanceAddress = validateAndParseAddress(nextAddress);
              setAddress(balanceAddress);
            } catch {
              balanceAddress = nextAddress;
              setAddress(nextAddress);
            }
          }
          void walletV6.requestChainId(wallet).then((nextChainId) => {
            const normalizedChainId = String(nextChainId);
            setChainId(normalizedChainId);
            if (normalizedChainId === STARKNET_MAINNET_CHAIN_ID) {
              void refreshPublicBalanceForAddress(balanceAddress).catch(() => undefined);
            } else {
              setPublicStrkBalance(null);
              setPublicBalances(emptyTokenBalances());
            }
          });
        });

        setWalletAccount(account);
        setSelectedWallet(wallet);
        setAddress(connectedAddress);
        setChainId(activeChainId);
        setSupportedSpecs(specs);
        setWalletApiVersions(apiVersions);

        const isPrivacyWallet = isReadyWallet(wallet.name);
        const reportsUnsupportedApi =
          (apiVersions.length > 0 && !supportsStrk20WalletApi(apiVersions)) ||
          (walletApiResult.status === "rejected" &&
            isUnsupportedWalletApiError(walletApiResult.reason));
        if (!isPrivacyWallet || reportsUnsupportedApi) {
          const detectedApiVersion = latestVersion(apiVersions);
          setShieldedBalance(null);
          setShieldedBalances(emptyTokenBalances());
          setPrivacyCapability("unsupported");
          setPrivacyMessage(
            !isPrivacyWallet
              ? "This wallet does not currently advertise Ready-compatible STRK20 support."
              : detectedApiVersion
                ? `Ready reports Wallet API ${detectedApiVersion}; STRK20 requires Wallet API 0.10.3 or newer. Update Ready and reconnect.`
                : "Ready does not expose a compatible STRK20 Wallet API. Update Ready and reconnect.",
          );
        } else {
          setPrivacyCapability("checking");
          setPrivacyMessage("Checking this account's private STRK balance…");
        }

        if (
          activeChainId === STARKNET_MAINNET_CHAIN_ID &&
          isPrivacyWallet &&
          !reportsUnsupportedApi
        ) {
          try {
            await refreshPublicBalanceForAddress(connectedAddress);
          } catch {
            // Connection still succeeds; the shield quote explains the unavailable balance.
          }
          try {
            await refreshBalanceForAccount(account);
          } catch {
            // Connection still succeeds; the page explains the missing capability.
          }
        }
      } catch (connectionError) {
        const message = describeError(connectionError);
        setError(message);
        clearConnection();
        throw new Error(message);
      } finally {
        setIsConnecting(false);
      }
    },
    [clearConnection, discoveredWallets, refreshBalanceForAccount, refreshPublicBalanceForAddress],
  );

  const disconnectWallet = useCallback(async () => {
    setError("");
    try {
      await selectedWallet?.features["standard:disconnect"].disconnect();
    } finally {
      clearConnection();
    }
  }, [clearConnection, selectedWallet]);

  const signPayoSession = useCallback(async (typedData: TypedData): Promise<string[]> => {
    if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
      throw new Error("Switch Ready to Starknet Mainnet before authorizing PAYO.");
    }
    const signature = await walletAccount.signMessage(typedData);
    if (!Array.isArray(signature) || signature.length < 2) {
      throw new Error("Ready returned an unsupported authentication signature.");
    }
    return signature.map((felt) => num.toHex(BigInt(felt)));
  }, [address, chainId, walletAccount]);

  const switchToMainnet = useCallback(async () => {
    if (!walletAccount) throw new Error("Connect Ready wallet first.");
    setError("");
    try {
      const switched = await walletAccount.switchStarknetChain(STARKNET_MAINNET_CHAIN_ID);
      if (!switched) throw new Error("Switch to Starknet Mainnet in Ready and try again.");
      setChainId(STARKNET_MAINNET_CHAIN_ID);
      try {
        await refreshPublicBalanceForAddress(address);
      } catch {
        // Switching succeeds even when the public balance RPC is temporarily unavailable.
      }
      if (privacyCapability !== "unsupported") {
        try {
          await refreshBalanceForAccount(walletAccount);
        } catch {
          // Switching succeeds even when a new account has no private state yet.
        }
      }
    } catch (switchError) {
      const message = describeError(switchError);
      setError(message);
      throw new Error(message);
    }
  }, [address, privacyCapability, refreshBalanceForAccount, refreshPublicBalanceForAddress, walletAccount]);

  const confirmTransaction = useCallback(
    async (hash: string, pending: PrivateTransaction, requestToken: symbol) => {
      try {
        await mainnetProvider.waitForTransaction(hash, { retries: 400, retryInterval: 3000 });
        // Chain finality is authoritative. Publish it before asking Ready for a
        // refreshed private balance: some Wallet API versions leave that
        // follow-up request unresolved even though the transaction succeeded.
        setTransaction({
          ...pending,
          stage: "confirmed",
          hash,
          balanceRefreshed: false,
        });
        if (privateActionLockRef.current === requestToken) {
          privateActionLockRef.current = null;
        }
        if (walletAccount) {
          try {
            const refreshedBalances = await refreshBalanceForAccount(walletAccount);
            const confirmed = { ...pending };
            if (
              pending.kind === "shield"
              && pending.token
              && pending.grossAmount !== undefined
              && pending.shieldedBalanceBefore !== undefined
            ) {
              const after = refreshedBalances[pending.token];
              const actualNet = after >= pending.shieldedBalanceBefore
                ? after - pending.shieldedBalanceBefore
                : 0n;
              if (actualNet <= pending.grossAmount) {
                confirmed.netAmount = actualNet;
                confirmed.walletFee = pending.grossAmount - actualNet;
                confirmed.feeQuoteExact = true;
              }
            }
            setTransaction((current) => current?.hash === hash
              ? {
                  ...current,
                  ...confirmed,
                  stage: "confirmed",
                  hash,
                  balanceRefreshed: true,
                  balanceRefreshError: undefined,
                }
              : current);
          } catch (refreshError) {
            setTransaction((current) => current?.hash === hash
              ? {
                  ...current,
                  balanceRefreshed: false,
                  balanceRefreshError: describeError(refreshError),
                }
              : current);
          }
        }
      } catch (confirmationError) {
        setTransaction({
          ...pending,
          stage: "failed",
          hash,
          error: describeError(confirmationError),
        });
      } finally {
        if (privateActionLockRef.current === requestToken) {
          privateActionLockRef.current = null;
        }
      }
    },
    [refreshBalanceForAccount, walletAccount],
  );

  const submitPrivateActions = useCallback(
    async (
      kind: "shield" | "payroll" | "wage_claim" | "wage_remediation",
      label: string,
      actions: STRK20_ACTION[],
      details: Pick<
        PrivateTransaction,
        "grossAmount" | "walletFee" | "feeToken" | "netAmount" | "token" | "totals" | "feeReserves" | "feeQuoteExact" | "shieldedBalanceBefore"
      > = {},
    ) => {
      if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
      if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
        throw new Error("Payo is connected to Starknet Mainnet. Switch network in Ready first.");
      }
      if (!isReadyWallet(selectedWallet?.name ?? "")) {
        throw new Error("Ready wallet is currently required for STRK20 privacy actions.");
      }
      if (privacyCapability === "unsupported") {
        throw new Error("This Ready version does not report STRK20 Wallet API support. Update it and reconnect.");
      }
      if (privacyCapability === "checking") {
        throw new Error("Wait for Ready to finish checking the private STRK account.");
      }
      if (privacyCapability === "uninitialized") {
        throw new Error(
          "Register this account in the STRK20 pool before shielding or running payroll.",
        );
      }
      if (privateActionLockRef.current) {
        throw new Error(
          "A private Mainnet transaction is already active. Do not approve a repeated Ready request.",
        );
      }

      const requestToken = Symbol(kind);
      privateActionLockRef.current = requestToken;
      const pending: PrivateTransaction = { kind, stage: "wallet", label, ...details };
      setError("");
      setTransaction(pending);
      try {
        const result = await walletAccount.strk20InvokeTransaction(actions);
        const confirming: PrivateTransaction = {
          ...pending,
          stage: "confirming",
          hash: result.transaction_hash,
        };
        setTransaction(confirming);
        void confirmTransaction(result.transaction_hash, confirming, requestToken);
        return result.transaction_hash;
      } catch (transactionError) {
        if (privateActionLockRef.current === requestToken) {
          privateActionLockRef.current = null;
        }
        const notRegistered = isNotRegisteredError(transactionError);
        const message = notRegistered
          ? "Ready returned NOT_REGISTERED (118). Complete the one-time STRK20 registration before shielding."
          : describeError(transactionError);
        if (notRegistered) {
          setShieldedBalance(null);
          setShieldedBalances(emptyTokenBalances());
          setPrivacyCapability("uninitialized");
          setPrivacyMessage(
            "This account is not registered in the STRK20 pool. Ready Wallet API 0.10.3 cannot register it from a dapp; complete the one-time STRK20 setup, then refresh.",
          );
        }
        setTransaction({ ...pending, stage: "failed", error: message });
        setError(message);
        throw new Error(message);
      }
    },
    [address, chainId, confirmTransaction, privacyCapability, selectedWallet?.name, walletAccount],
  );

  const requestPrivateFeeQuote = useCallback(
    async (tokenSymbol: PayrollTokenSymbol): Promise<PrivateFeeQuote> => {
      if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
      if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
        throw new Error("Switch Ready to Starknet Mainnet before requesting a private fee quote.");
      }
      if (privacyCapability === "unsupported" || privacyCapability === "uninitialized") {
        throw new Error("This account cannot request a STRK20 fee quote yet.");
      }
      assertPrivacyTokenEnabled(tokenSymbol);
      const response = await fetch(`/api/v1/strk20-fee-quote?token=${tokenSymbol}`, {
        cache: "no-store",
      });
      const payload = await response.json() as {
        token?: string;
        walletFee?: string;
        exact?: boolean;
        source?: string;
        quotedAt?: number;
        error?: { message?: string };
      };
      if (!response.ok) {
        throw new Error(payload.error?.message ?? "The live STRK20 fee quote is unavailable.");
      }
      if (
        payload.token !== tokenSymbol
        || typeof payload.walletFee !== "string"
        || typeof payload.exact !== "boolean"
        || (payload.source !== "pool-onchain" && payload.source !== "paymaster-live-estimate")
        || !Number.isSafeInteger(payload.quotedAt)
      ) {
        throw new Error("The live STRK20 fee service returned an invalid quote.");
      }
      const walletFee = BigInt(payload.walletFee);
      if (walletFee <= 0n) throw new Error("The live STRK20 fee service returned a zero fee.");
      return {
        token: tokenSymbol,
        walletFee,
        source: payload.source,
        exact: payload.exact,
        quotedAt: payload.quotedAt!,
      };
    },
    [address, chainId, privacyCapability, walletAccount],
  );

  const quoteShieldToken = useCallback(
    async (tokenSymbol: PayrollTokenSymbol, amount: string): Promise<ShieldFeeQuote> => {
      const token = PAYROLL_TOKENS[tokenSymbol];
      const grossAmount = parseTokenAmount(amount, token);
      const quote = await requestPrivateFeeQuote(tokenSymbol);
      if (grossAmount <= quote.walletFee) {
        throw new Error(
          `Enter more than ${formatTokenAmount(quote.walletFee, token)} ${token.symbol} to cover the live private fee reserve.`,
        );
      }
      return {
        ...quote,
        grossAmount,
        netAmount: grossAmount - quote.walletFee,
      };
    },
    [requestPrivateFeeQuote],
  );

  const shieldToken = useCallback(
    async (tokenSymbol: PayrollTokenSymbol, amount: string, suppliedQuote?: ShieldFeeQuote) => {
      if (!address) throw new Error("Connect Ready wallet first.");
      const token = PAYROLL_TOKENS[tokenSymbol];
      assertPrivacyTokenEnabled(tokenSymbol);
      const grossAmount = parseTokenAmount(amount, token);
      const quoteIsFresh = suppliedQuote?.token === tokenSymbol
        && suppliedQuote.grossAmount === grossAmount
        && Date.now() - suppliedQuote.quotedAt >= 0
        && Date.now() - suppliedQuote.quotedAt <= 30_000;
      const [quote, currentPublicBalances] = await Promise.all([
        quoteIsFresh ? Promise.resolve(suppliedQuote) : quoteShieldToken(tokenSymbol, amount),
        refreshPublicBalanceForAddress(address),
      ]);
      const currentTokenBalance = currentPublicBalances[tokenSymbol];
      if (grossAmount > currentTokenBalance) {
        throw new Error(
          `Insufficient public ${token.symbol} balance. Available ${formatTokenAmount(currentTokenBalance, token)} ${token.symbol}; entered ${formatTokenAmount(grossAmount, token)} ${token.symbol}.`,
        );
      }

      return submitPrivateActions(
        "shield",
        `${formatTokenAmount(quote.netAmount, token)} ${token.symbol} shielded`,
        [{ type: "deposit", token: token.address, amount: num.toHex(grossAmount) }],
        {
          grossAmount,
          walletFee: quote.walletFee,
          feeToken: quote.token,
          netAmount: quote.netAmount,
          token: token.symbol,
          feeQuoteExact: quote.exact,
          shieldedBalanceBefore: shieldedBalances[tokenSymbol] ?? undefined,
        },
      );
    },
    [address, quoteShieldToken, refreshPublicBalanceForAddress, shieldedBalances, submitPrivateActions],
  );

  const shieldStrk = useCallback(
    (amount: string) => shieldToken("STRK", amount),
    [shieldToken],
  );

  const runProofBoundPayroll = useCallback(
    async (recipients: PayrollRecipient[], payoAction: STRK20_INVOKE_ACTION) => {
      const configuredSeal = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
      const { actions, totals } = buildPrivatePayrollActions(
        recipients,
        payoAction,
        configuredSeal ?? "",
      );

      if (!walletAccount) throw new Error("Connect Ready wallet first.");
      const activeTokens = PAYROLL_TOKEN_LIST.filter((token) => totals[token.symbol] > 0n);
      const [feeQuotes, currentShieldedBalances] = await Promise.all([
        Promise.all(activeTokens.map((token) => requestPrivateFeeQuote(token.symbol))),
        refreshBalanceForAccount(walletAccount),
      ]);
      const feeReserves: Record<PayrollTokenSymbol, bigint> = { STRK: 0n, USDC: 0n };
      for (const quote of feeQuotes) feeReserves[quote.token] = quote.walletFee;
      const requiredReserves = requiredPayrollReservesForQuotes(totals, feeReserves);

      for (const token of PAYROLL_TOKEN_LIST) {
        const balance = currentShieldedBalances[token.symbol];
        const required = requiredReserves[token.symbol];
        if (required > 0n && (balance === null || required > balance)) {
          throw new Error(
            `The shielded ${token.symbol} treasury does not cover this payroll and its passive fee reserve. Required ${formatTokenAmount(required, token)} ${token.symbol} (${formatTokenAmount(totals[token.symbol], token)} payroll + ${formatTokenAmount(feeReserves[token.symbol], token)} fee); available ${formatTokenAmount(balance, token)} ${token.symbol}.`,
          );
        }
      }

      const singleFeeQuote = feeQuotes.length === 1 ? feeQuotes[0] : undefined;

      return submitPrivateActions(
        "payroll",
        `${recipients.length} private ${recipients.length === 1 ? "payment" : "payments"}`,
        actions,
        {
          totals,
          feeReserves,
          walletFee: singleFeeQuote?.walletFee,
          feeToken: singleFeeQuote?.token,
          feeQuoteExact: feeQuotes.every((quote) => quote.exact),
        },
      );
    },
    [refreshBalanceForAccount, requestPrivateFeeQuote, submitPrivateActions, walletAccount],
  );

  const runProofBoundException = useCallback(
    async (
      workflow: PrivateExceptionWorkflow,
      recipients: PayrollRecipient[],
      payoAction: STRK20_INVOKE_ACTION,
    ) => {
      const configuredSeal = process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS;
      const { actions, totals } = buildPrivateExceptionActions(
        workflow,
        recipients,
        payoAction,
        configuredSeal ?? "",
      );
      if (!walletAccount) throw new Error("Connect Ready wallet first.");
      const feeTokens = workflow === "wage_claim"
        ? [PAYROLL_TOKENS.STRK]
        : PAYROLL_TOKEN_LIST.filter((token) => totals[token.symbol] > 0n);
      const [feeQuotes, currentShieldedBalances] = await Promise.all([
        Promise.all(feeTokens.map((token) => requestPrivateFeeQuote(token.symbol))),
        refreshBalanceForAccount(walletAccount),
      ]);
      const feeReserves: Record<PayrollTokenSymbol, bigint> = { STRK: 0n, USDC: 0n };
      for (const quote of feeQuotes) feeReserves[quote.token] = quote.walletFee;
      const requiredReserves = requiredPayrollReservesForQuotes(totals, feeReserves);
      for (const token of PAYROLL_TOKEN_LIST) {
        const required = requiredReserves[token.symbol];
        const balance = currentShieldedBalances[token.symbol];
        if (required > 0n && (balance === null || required > balance)) {
          throw new Error(
            `The shielded ${token.symbol} treasury does not cover this ${workflow.replaceAll("_", " ")} and its private fee reserve. Required ${formatTokenAmount(required, token)} ${token.symbol}; available ${formatTokenAmount(balance, token)} ${token.symbol}.`,
          );
        }
      }
      const singleFeeQuote = feeQuotes.length === 1 ? feeQuotes[0] : undefined;
      return submitPrivateActions(
        workflow,
        workflow === "wage_claim" ? "Private wage claim" : "Private wage remediation",
        actions,
        {
          totals,
          feeReserves,
          walletFee: singleFeeQuote?.walletFee,
          feeToken: singleFeeQuote?.token,
          feeQuoteExact: feeQuotes.every((quote) => quote.exact),
        },
      );
    },
    [refreshBalanceForAccount, requestPrivateFeeQuote, submitPrivateActions, walletAccount],
  );

  const reconcilePayrollTransaction = useCallback(async (transactionHash: string) => {
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
      throw new Error("PAYO recovered an invalid Starknet transaction hash.");
    }
    // Ready may submit the STRK20 transaction but leave the Wallet API promise
    // unresolved. Once PAYO's canonical seal indexer recovers that hash, release
    // the browser lock and reconcile the visible wallet state without issuing a
    // second request.
    privateActionLockRef.current = null;
    setError("");
    setTransaction((current) => ({
      ...(current?.kind === "payroll"
        ? current
        : { kind: "payroll" as const, label: "Private payroll recovered on-chain" }),
      stage: "confirmed",
      hash: transactionHash,
      balanceRefreshed: false,
      balanceRefreshError: undefined,
    }));
    if (walletAccount) {
      void refreshBalanceForAccount(walletAccount).then(() => {
        setTransaction((current) => current?.kind === "payroll" && current.hash === transactionHash
          ? { ...current, balanceRefreshed: true, balanceRefreshError: undefined }
          : current);
      }).catch((refreshError) => {
        setTransaction((current) => current?.kind === "payroll" && current.hash === transactionHash
          ? { ...current, balanceRefreshed: false, balanceRefreshError: describeError(refreshError) }
          : current);
      });
    }
  }, [refreshBalanceForAccount, walletAccount]);

  const scheduleObligationRoot = useCallback(async (
    agreementRoot: string,
  ): Promise<ObligationRootScheduleResult> => {
    if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
      throw new Error("Switch Ready to Starknet Mainnet before scheduling an obligation root.");
    }
    const registryAddress = process.env.NEXT_PUBLIC_PAYO_OBLIGATION_REGISTRY_ADDRESS;
    if (!registryAddress) {
      throw new Error("The PAYO obligation registry is not deployed/configured.");
    }
    if (privateActionLockRef.current) {
      throw new Error("A Mainnet wallet request is already active.");
    }
    const { high, low } = rootLimbs(agreementRoot);
    const [latest, ownerResponse] = await Promise.all([
      mainnetProvider.getBlock("latest"),
      mainnetProvider.callContract({
        contractAddress: registryAddress,
        entrypoint: "get_obligation_root_owner",
        calldata: [high.toString(), low.toString()],
      }),
    ]);
    const rootOwner = validateAndParseAddress(ownerResponse[0] ?? "0x0");
    if (num.toBigInt(rootOwner) !== 0n && num.toBigInt(rootOwner) !== num.toBigInt(address)) {
      throw new Error(
        `This obligation root belongs to ${shortStarknetAddress(rootOwner)}, not connected wallet ${shortStarknetAddress(address)}.`,
      );
    }
    const schedule = prepareObligationRootSchedule({
      registryAddress,
      agreementRoot,
      blockTimestamp: Number(latest.timestamp),
    });
    const requestToken = Symbol("registry");
    privateActionLockRef.current = requestToken;
    const pending: PrivateTransaction = {
      kind: "registry",
      stage: "wallet",
      label: "Schedule private payroll root",
    };
    setError("");
    setTransaction(pending);
    try {
      const result = await walletAccount.execute(schedule.call);
      const confirming: PrivateTransaction = {
        ...pending,
        stage: "confirming",
        hash: result.transaction_hash,
      };
      setTransaction(confirming);
      await mainnetProvider.waitForTransaction(result.transaction_hash, {
        retries: 400,
        retryInterval: 3_000,
      });
      const [active, confirmedOwner] = await Promise.all([
        mainnetProvider.callContract({
          contractAddress: registryAddress,
          entrypoint: "is_obligation_root_valid",
          calldata: [high.toString(), low.toString()],
        }),
        mainnetProvider.callContract({
          contractAddress: registryAddress,
          entrypoint: "get_obligation_root_owner",
          calldata: [high.toString(), low.toString()],
        }),
      ]);
      if (num.toBigInt(active[0] ?? "0x0") === 0n) {
        throw new Error("The obligation root confirmed but did not activate immediately.");
      }
      if (num.toBigInt(confirmedOwner[0] ?? "0x0") !== num.toBigInt(address)) {
        throw new Error("The obligation root confirmed without assigning the connected organization owner.");
      }
      setTransaction({ ...confirming, stage: "confirmed" });
      return {
        transactionHash: result.transaction_hash,
        validAfter: schedule.validAfter,
        expiresAt: schedule.expiresAt,
      };
    } catch (scheduleError) {
      const message = describeError(scheduleError);
      setTransaction({ ...pending, stage: "failed", error: message });
      setError(message);
      throw new Error(message);
    } finally {
      if (privateActionLockRef.current === requestToken) privateActionLockRef.current = null;
    }
  }, [address, chainId, walletAccount]);

  const isObligationRootActive = useCallback(async (agreementRoot: string): Promise<boolean> => {
    const registryAddress = process.env.NEXT_PUBLIC_PAYO_OBLIGATION_REGISTRY_ADDRESS;
    if (!registryAddress) throw new Error("The PAYO obligation registry is not deployed/configured.");
    if (!/^0x[0-9a-fA-F]{64}$/.test(agreementRoot)) {
      throw new Error("The obligation root must be a canonical 32-byte value.");
    }
    const { high, low } = rootLimbs(agreementRoot);
    const response = await mainnetProvider.callContract({
      contractAddress: registryAddress,
      entrypoint: "is_obligation_root_valid",
      calldata: [high.toString(), low.toString()],
    });
    return num.toBigInt(response[0] ?? "0x0") !== 0n;
  }, []);

  const getObligationRootOwner = useCallback(async (agreementRoot: string): Promise<string> => {
    const registryAddress = process.env.NEXT_PUBLIC_PAYO_OBLIGATION_REGISTRY_ADDRESS;
    if (!registryAddress) throw new Error("The PAYO obligation registry is not deployed/configured.");
    const { high, low } = rootLimbs(agreementRoot);
    const response = await mainnetProvider.callContract({
      contractAddress: registryAddress,
      entrypoint: "get_obligation_root_owner",
      calldata: [high.toString(), low.toString()],
    });
    return validateAndParseAddress(response[0] ?? "0x0");
  }, []);

  const isFxRootActive = useCallback(async (fxRoot: string): Promise<boolean> => {
    const registryAddress = process.env.NEXT_PUBLIC_PAYO_POLICY_REGISTRY_ADDRESS;
    if (!registryAddress) throw new Error("The PAYO policy/FX registry is not deployed/configured.");
    const { high, low } = rootLimbs(fxRoot);
    const response = await mainnetProvider.callContract({
      contractAddress: registryAddress,
      entrypoint: "is_fx_root_valid",
      calldata: [high.toString(), low.toString()],
    });
    return num.toBigInt(response[0] ?? "0x0") !== 0n;
  }, []);

  const publishFxRoot = useCallback(async (input: {
    root: string;
    observedAt: number;
    maximumAgeSeconds: number;
  }): Promise<string> => {
    if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
      throw new Error("Switch Ready to Starknet Mainnet before publishing an FX root.");
    }
    const registryAddress = process.env.NEXT_PUBLIC_PAYO_POLICY_REGISTRY_ADDRESS;
    if (!registryAddress) throw new Error("The PAYO policy/FX registry is not deployed/configured.");
    if (privateActionLockRef.current) throw new Error("A Mainnet wallet request is already active.");
    const [latest, publisherResponse] = await Promise.all([
      mainnetProvider.getBlock("latest"),
      mainnetProvider.callContract({
        contractAddress: registryAddress,
        entrypoint: "get_fx_publisher",
        calldata: [],
      }),
    ]);
    const publisher = validateAndParseAddress(publisherResponse[0] ?? "0x0");
    if (num.toBigInt(publisher) !== num.toBigInt(address)) {
      throw new Error(
        `Connected wallet ${shortStarknetAddress(address)} is not the FX publisher ${shortStarknetAddress(publisher)}.`,
      );
    }
    const call = prepareFxRootPublication({
      registryAddress,
      fxRoot: input.root,
      observedAt: input.observedAt,
      maximumAgeSeconds: input.maximumAgeSeconds,
      blockTimestamp: Number(latest.timestamp),
    });
    const requestToken = Symbol("registry");
    privateActionLockRef.current = requestToken;
    const pending: PrivateTransaction = {
      kind: "registry",
      stage: "wallet",
      label: "Authorize fresh Pragma FX root",
    };
    setError("");
    setTransaction(pending);
    try {
      const result = await walletAccount.execute(call);
      const confirming: PrivateTransaction = {
        ...pending,
        stage: "confirming",
        hash: result.transaction_hash,
      };
      setTransaction(confirming);
      await mainnetProvider.waitForTransaction(result.transaction_hash, {
        retries: 400,
        retryInterval: 3_000,
      });
      setTransaction({ ...confirming, stage: "confirmed" });
      return result.transaction_hash;
    } catch (publicationError) {
      const message = describeError(publicationError);
      setTransaction({ ...pending, stage: "failed", error: message });
      setError(message);
      throw new Error(message);
    } finally {
      if (privateActionLockRef.current === requestToken) privateActionLockRef.current = null;
    }
  }, [address, chainId, walletAccount]);

  const deployPayoMainnet = useCallback(async (
    deploymentPackage: PayoBrowserDeploymentPackage,
    onProgress?: (progress: PayoDeploymentProgress) => void,
  ): Promise<PayoMainnetDeploymentResult> => {
    if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
      throw new Error("Switch Ready to Starknet Mainnet before deploying PAYO.");
    }
    if (!isReadyWallet(selectedWallet?.name ?? "")) {
      throw new Error("The guarded deployment operator currently requires Ready wallet.");
    }
    if (privateActionLockRef.current) throw new Error("A Mainnet wallet request is already active.");
    if (deploymentPackage.schemaVersion !== 1) {
      throw new Error("The PAYO deployment package version is unsupported.");
    }
    for (const name of PAYO_DEPLOYMENT_ARTIFACT_NAMES) {
      const artifact = deploymentPackage.artifacts[name];
      if (!artifact) throw new Error(`The PAYO deployment package is missing ${name}.`);
      const classHash = num.toHex(BigInt(hash.computeContractClassHash(artifact.contract)));
      const compiledClassHash = num.toHex(BigInt(hash.computeCompiledClassHash(artifact.casm)));
      if (
        BigInt(classHash) !== BigInt(artifact.classHash)
        || BigInt(compiledClassHash) !== BigInt(artifact.compiledClassHash)
      ) {
        throw new Error(`${name} does not match its reviewed deployment hashes.`);
      }
    }
    const plan = buildPayoMainnetTopologyPlan({
      adminAddress: address,
      artifacts: deploymentPackage.artifacts,
    });
    const requestToken = Symbol("deployment");
    privateActionLockRef.current = requestToken;
    const pending: PrivateTransaction = {
      kind: "deployment",
      stage: "wallet",
      label: "Deploy PAYO proof contracts",
    };
    setError("");
    setTransaction(pending);
    const declarations: Partial<Record<PayoDeploymentArtifactName, string>> = {};
    let deploymentTransactionHash: string | null = null;
    try {
      const classExists = async (classHash: string) => {
        try {
          await mainnetProvider.getClass(classHash, "latest");
          return true;
        } catch (classError) {
          if (missingStarknetClass(classError)) return false;
          throw classError;
        }
      };
      const deployedClassHash = async (contractAddress: string) => {
        try {
          return num.toHex(BigInt(await mainnetProvider.getClassHashAt(contractAddress, "latest")));
        } catch (contractError) {
          if (missingStarknetContract(contractError)) return null;
          throw contractError;
        }
      };

      for (const name of PAYO_DEPLOYMENT_ARTIFACT_NAMES) {
        const artifact = deploymentPackage.artifacts[name];
        onProgress?.({
          stage: "checking",
          contract: name,
          message: `Checking ${name} class on Mainnet…`,
        });
        if (await classExists(artifact.classHash)) continue;
        onProgress?.({
          stage: "declaring",
          contract: name,
          message: `Review Ready's simulation and approve the ${name} declaration.`,
        });
        const declaration = await walletAccount.declare({
          contract: artifact.contract,
          casm: artifact.casm,
        });
        declarations[name] = declaration.transaction_hash;
        onProgress?.({
          stage: "declaring",
          contract: name,
          transactionHash: declaration.transaction_hash,
          message: `Confirming ${name} declaration…`,
        });
        await mainnetProvider.waitForTransaction(declaration.transaction_hash, {
          retries: 400,
          retryInterval: 3_000,
        });
        if (!(await classExists(artifact.classHash))) {
          throw new Error(`${name} was not declared after its transaction confirmed.`);
        }
      }

      const deploymentPayloads = [];
      for (const name of PAYO_DEPLOYMENT_ARTIFACT_NAMES) {
        const planned = plan.contracts[name];
        const currentClassHash = await deployedClassHash(planned.address);
        if (currentClassHash !== null) {
          if (BigInt(currentClassHash) !== BigInt(planned.classHash)) {
            throw new Error(`${name} predicted address contains an unexpected class.`);
          }
          continue;
        }
        deploymentPayloads.push({
          classHash: planned.classHash,
          constructorCalldata: planned.constructorCalldata,
          salt: planned.salt,
          unique: false,
        });
      }
      if (deploymentPayloads.length > 0) {
        onProgress?.({
          stage: "deploying",
          message: "Review Ready's simulation and deploy the five-contract PAYO topology.",
        });
        const deployment = await walletAccount.deploy(deploymentPayloads);
        deploymentTransactionHash = deployment.transaction_hash;
        setTransaction({ ...pending, stage: "confirming", hash: deploymentTransactionHash });
        onProgress?.({
          stage: "deploying",
          transactionHash: deploymentTransactionHash,
          message: "Confirming the PAYO deployment topology…",
        });
        await mainnetProvider.waitForTransaction(deploymentTransactionHash, {
          retries: 400,
          retryInterval: 3_000,
        });
      }

      onProgress?.({ stage: "verifying", message: "Reading every PAYO binding back from Mainnet…" });
      const verifiedBlockNumber = await mainnetProvider.getBlockNumber();
      for (const name of PAYO_DEPLOYMENT_ARTIFACT_NAMES) {
        const planned = plan.contracts[name];
        const currentClassHash = await mainnetProvider.getClassHashAt(
          planned.address,
          verifiedBlockNumber,
        );
        if (BigInt(currentClassHash) !== BigInt(planned.classHash)) {
          throw new Error(`${name} failed deployed class-hash verification.`);
        }
      }
      const calls = [
        [plan.contracts.bundleVerifier.address, "get_underlying_verifier", plan.contracts.generatedVerifier.address],
        [plan.contracts.policyRegistry.address, "get_admin", plan.adminAddress],
        [plan.contracts.policyRegistry.address, "get_fx_publisher", plan.adminAddress],
        [plan.contracts.obligationRegistry.address, "get_admin", plan.adminAddress],
        [plan.contracts.payrollSeal.address, "get_pool", plan.poolAddress],
        [plan.contracts.payrollSeal.address, "get_catalog_registry", plan.contracts.policyRegistry.address],
        [plan.contracts.payrollSeal.address, "get_obligation_registry", plan.contracts.obligationRegistry.address],
      ] as const;
      for (const [contractAddress, entrypoint, expected] of calls) {
        const response = await mainnetProvider.callContract(
          { contractAddress, entrypoint, calldata: [] },
          verifiedBlockNumber,
        );
        if (response.length !== 1 || BigInt(response[0]) !== BigInt(expected)) {
          throw new Error(`${entrypoint} returned an unexpected deployed binding.`);
        }
      }
      setTransaction({
        ...pending,
        stage: "confirmed",
        hash: deploymentTransactionHash ?? Object.values(declarations).at(-1),
      });
      return {
        plan,
        declarationTransactionHashes: declarations,
        deploymentTransactionHash,
        verifiedBlockNumber,
      };
    } catch (deploymentError) {
      const message = describeError(deploymentError);
      setTransaction({
        ...pending,
        stage: "failed",
        hash: deploymentTransactionHash ?? undefined,
        error: message,
      });
      setError(message);
      throw new Error(message);
    } finally {
      if (privateActionLockRef.current === requestToken) privateActionLockRef.current = null;
    }
  }, [address, chainId, selectedWallet?.name, walletAccount]);

  const schedulePayoBaseline = useCallback(async (
    plan: PayoMainnetTopologyPlan,
    policyRoot: string,
  ): Promise<PayoBaselineScheduleResult> => {
    if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID || BigInt(plan.chainId) !== BigInt(chainId)) {
      throw new Error("The PAYO baseline must be scheduled on Starknet Mainnet.");
    }
    if (BigInt(plan.adminAddress) !== BigInt(address)) {
      throw new Error("The connected Ready address is not the planned PAYO administrator.");
    }
    if (privateActionLockRef.current) throw new Error("A Mainnet wallet request is already active.");
    const block = await mainnetProvider.getBlock("latest");
    const baseline = preparePayoBaselineSchedule({
      registryAddress: plan.contracts.policyRegistry.address,
      bundleVerifierAddress: plan.contracts.bundleVerifier.address,
      policyRoot,
      blockTimestamp: Number(block.timestamp),
    });
    const [policyAdmin, obligationAdmin] = await Promise.all([
      mainnetProvider.callContract({
        contractAddress: plan.contracts.policyRegistry.address,
        entrypoint: "get_admin",
        calldata: [],
      }),
      mainnetProvider.callContract({
        contractAddress: plan.contracts.obligationRegistry.address,
        entrypoint: "get_admin",
        calldata: [],
      }),
    ]);
    if (
      BigInt(policyAdmin[0] ?? 0) !== BigInt(address)
      || BigInt(obligationAdmin[0] ?? 0) !== BigInt(address)
    ) {
      throw new Error("The connected Ready address does not control both PAYO registries.");
    }
    const requestToken = Symbol("registry");
    privateActionLockRef.current = requestToken;
    const pending: PrivateTransaction = {
      kind: "registry",
      stage: "wallet",
      label: "Schedule PAYO policy and verifier",
    };
    setError("");
    setTransaction(pending);
    try {
      const scheduled = await walletAccount.execute(baseline.calls);
      const confirming = { ...pending, stage: "confirming" as const, hash: scheduled.transaction_hash };
      setTransaction(confirming);
      await mainnetProvider.waitForTransaction(scheduled.transaction_hash, {
        retries: 400,
        retryInterval: 3_000,
      });
      const { high, low } = rootLimbs(policyRoot);
      const [policyActive, verifierActive] = await Promise.all([
        mainnetProvider.callContract({
          contractAddress: plan.contracts.policyRegistry.address,
          entrypoint: "is_policy_root_valid",
          calldata: [high.toString(), low.toString()],
        }),
        mainnetProvider.callContract({
          contractAddress: plan.contracts.policyRegistry.address,
          entrypoint: "is_verifier_valid",
          calldata: ["0", "1"],
        }),
      ]);
      if (
        num.toBigInt(policyActive[0] ?? "0x0") === 0n
        || num.toBigInt(verifierActive[0] ?? "0x0") === 0n
      ) {
        throw new Error("The PAYO baseline confirmed but did not activate immediately.");
      }
      setTransaction({ ...confirming, stage: "confirmed" });
      return {
        transactionHash: scheduled.transaction_hash,
        policyRoot,
        validAfter: baseline.validAfter,
        expiresAt: baseline.expiresAt,
      };
    } catch (scheduleError) {
      const message = describeError(scheduleError);
      setTransaction({ ...pending, stage: "failed", error: message });
      setError(message);
      throw new Error(message);
    } finally {
      if (privateActionLockRef.current === requestToken) privateActionLockRef.current = null;
    }
  }, [address, chainId, walletAccount]);

  const readPayoPhase3Activation = useCallback(async (): Promise<PayoPhase3ActivationStatus> => {
    const deployment = PAYO_PHASE3_MAINNET_DEPLOYMENT;
    const blockNumber = await mainnetProvider.getBlockNumber();
    const [
      chain,
      registryAdmin,
      sealClassHash,
      sealPool,
      sealPolicyRegistry,
      sealObligationRegistry,
      ...bundleClassHashes
    ] = await Promise.all([
      mainnetProvider.getChainId(),
      mainnetProvider.callContract({
        contractAddress: deployment.policyRegistryAddress,
        entrypoint: "get_admin",
        calldata: [],
      }, blockNumber),
      mainnetProvider.getClassHashAt(deployment.sealAddress, blockNumber),
      mainnetProvider.callContract({
        contractAddress: deployment.sealAddress,
        entrypoint: "get_pool",
        calldata: [],
      }, blockNumber),
      mainnetProvider.callContract({
        contractAddress: deployment.sealAddress,
        entrypoint: "get_catalog_registry",
        calldata: [],
      }, blockNumber),
      mainnetProvider.callContract({
        contractAddress: deployment.sealAddress,
        entrypoint: "get_obligation_registry",
        calldata: [],
      }, blockNumber),
      ...deployment.profiles.map((profile) =>
        mainnetProvider.getClassHashAt(profile.bundleAddress, blockNumber)),
    ]);
    const topologyReady = (
      BigInt(chain) === BigInt(STARKNET_MAINNET_CHAIN_ID)
      && BigInt(registryAdmin[0] ?? 0) === BigInt(deployment.adminAddress)
      && BigInt(sealClassHash) === BigInt(deployment.sealClassHash)
      && BigInt(sealPool[0] ?? 0) === BigInt(STRK20_MAINNET_POOL_ADDRESS)
      && BigInt(sealPolicyRegistry[0] ?? 0) === BigInt(deployment.policyRegistryAddress)
      && BigInt(sealObligationRegistry[0] ?? 0) === BigInt(deployment.obligationRegistryAddress)
      && bundleClassHashes.every((classHash, index) =>
        BigInt(classHash) === BigInt(deployment.profiles[index].bundleClassHash))
    );
    if (!topologyReady) {
      throw new Error("The live Phase 3 Mainnet topology does not match the reviewed deployment.");
    }
    const profiles = await Promise.all(deployment.profiles.map(async (profile) => {
      const valid = await mainnetProvider.callContract({
        contractAddress: deployment.policyRegistryAddress,
        entrypoint: "is_verifier_valid",
        calldata: [profile.mode.toString(), profile.proofVersion.toString()],
      }, blockNumber);
      let active = num.toBigInt(valid[0] ?? "0x0") !== 0n;
      if (active) {
        const configured = await mainnetProvider.callContract({
          contractAddress: deployment.policyRegistryAddress,
          entrypoint: "get_verifier",
          calldata: [profile.mode.toString(), profile.proofVersion.toString()],
        }, blockNumber);
        active = BigInt(configured[0] ?? 0) === BigInt(profile.bundleAddress);
      }
      return {
        name: profile.name,
        mode: profile.mode,
        proofVersion: profile.proofVersion,
        bundleAddress: profile.bundleAddress,
        active,
      };
    }));
    return {
      blockNumber,
      topologyReady,
      walletIsAdmin: Boolean(address && BigInt(address) === BigInt(deployment.adminAddress)),
      allActive: profiles.every((profile) => profile.active),
      profiles,
    };
  }, [address]);

  const activatePayoPhase3 = useCallback(async (): Promise<PayoPhase3ActivationResult> => {
    if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
    if (chainId !== STARKNET_MAINNET_CHAIN_ID) {
      throw new Error("Phase 3 activation must be signed on Starknet Mainnet.");
    }
    const deployment = PAYO_PHASE3_MAINNET_DEPLOYMENT;
    if (BigInt(address) !== BigInt(deployment.adminAddress)) {
      throw new Error("The connected Ready wallet is not the PAYO registry administrator.");
    }
    if (privateActionLockRef.current) throw new Error("A Mainnet wallet request is already active.");
    const preflight = await readPayoPhase3Activation();
    if (!preflight.topologyReady || !preflight.walletIsAdmin) {
      throw new Error("Phase 3 activation preflight did not pass.");
    }
    if (preflight.allActive) throw new Error("All Phase 3 verifier profiles are already active.");
    const block = await mainnetProvider.getBlock("latest");
    const schedule = preparePayoPhase3VerifierSchedule({
      registryAddress: deployment.policyRegistryAddress,
      profiles: deployment.profiles,
      blockTimestamp: Number(block.timestamp),
    });
    const requestToken = Symbol("phase3-registry");
    privateActionLockRef.current = requestToken;
    const pending: PrivateTransaction = {
      kind: "registry",
      stage: "wallet",
      label: "Activate PAYO Phase 3 verifiers",
    };
    setError("");
    setTransaction(pending);
    try {
      const submitted = await walletAccount.execute(schedule.calls);
      const confirming = {
        ...pending,
        stage: "confirming" as const,
        hash: submitted.transaction_hash,
      };
      setTransaction(confirming);
      await mainnetProvider.waitForTransaction(submitted.transaction_hash, {
        retries: 400,
        retryInterval: 3_000,
      });
      const status = await readPayoPhase3Activation();
      if (!status.allActive) {
        throw new Error("The activation confirmed but one or more verifier profiles are inactive.");
      }
      setTransaction({ ...confirming, stage: "confirmed" });
      return {
        transactionHash: submitted.transaction_hash,
        validAfter: schedule.validAfter,
        expiresAt: schedule.expiresAt,
        status,
      };
    } catch (activationError) {
      const message = describeError(activationError);
      setTransaction({ ...pending, stage: "failed", error: message });
      setError(message);
      throw new Error(message);
    } finally {
      if (privateActionLockRef.current === requestToken) privateActionLockRef.current = null;
    }
  }, [address, chainId, readPayoPhase3Activation, walletAccount]);

  const isConnected = Boolean(walletAccount && address);
  const isMainnet = chainId === STARKNET_MAINNET_CHAIN_ID;
  const networkName = !chainId
    ? "Mainnet"
    : isMainnet
      ? "Mainnet"
      : chainId === starknetConstants.StarknetChainId.SN_SEPOLIA
        ? "Sepolia"
        : "Unsupported";

  const wallets = useMemo(
    () =>
      discoveredWallets.map((wallet) => ({
        name: wallet.name,
        icon: wallet.icon,
        privacyReady: isReadyWallet(wallet.name),
      })),
    [discoveredWallets],
  );
  const walletApiVersion = latestVersion(walletApiVersions);

  const value: StarknetWalletContextValue = {
    wallets,
    discoveryReady,
    isConnected,
    isConnecting,
    walletName: selectedWallet?.name ?? "",
    address,
    chainId,
    networkName,
    isMainnet,
    supportedSpecs,
    walletApiVersions,
    walletApiVersion,
    privacyCapability,
    privacyMessage,
    shieldedBalances,
    publicBalances,
    shieldedBalance,
    publicStrkBalance,
    isRefreshingPublicBalance,
    publicBalanceError,
    isRefreshingBalance,
    transaction,
    error,
    connectWallet,
    disconnectWallet,
    signPayoSession,
    switchToMainnet,
    refreshPublicBalance,
    refreshBalance,
    quoteShieldToken,
    shieldToken,
    shieldStrk,
    runProofBoundPayroll,
    runProofBoundException,
    reconcilePayrollTransaction,
    scheduleObligationRoot,
    isObligationRootActive,
    getObligationRootOwner,
    publishFxRoot,
    isFxRootActive,
    deployPayoMainnet,
    schedulePayoBaseline,
    readPayoPhase3Activation,
    activatePayoPhase3,
    clearTransaction: () => setTransaction(null),
  };

  return <StarknetWalletContext.Provider value={value}>{children}</StarknetWalletContext.Provider>;
}

export function useStarknetWallet() {
  const context = useContext(StarknetWalletContext);
  if (!context) throw new Error("useStarknetWallet must be used within StarknetWalletProvider");
  return context;
}
