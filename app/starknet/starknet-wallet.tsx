"use client";

import { createStore, type Store } from "@starknet-io/get-starknet-discovery";
import type { WalletWithStarknetFeatures } from "@starknet-io/get-starknet-wallet-standard/features";
import {
  constants as starknetConstants,
  num,
  RpcProvider,
  uint256,
  validateAndParseAddress,
  WalletAccountV6,
  walletV6,
  type STRK20_ACTION,
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

export const STRK_TOKEN_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
export const STRK20_MAINNET_POOL_ADDRESS =
  "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
export const STRK20_SETUP_URL = "https://strk20.starknet.io/app";
export const STARKNET_MAINNET_CHAIN_ID = starknetConstants.StarknetChainId.SN_MAIN;
export const STARKNET_MAINNET_EXPLORER = "https://starkscan.co";

const starknetRpcUrl =
  process.env.NEXT_PUBLIC_STARKNET_RPC_URL ?? "https://rpc.starknet.lava.build";
const mainnetProvider = new RpcProvider({ nodeUrl: starknetRpcUrl });

export type PayrollRecipient = {
  address: string;
  amount: string;
};

export type WalletChoice = {
  name: string;
  icon: string;
  privacyReady: boolean;
};

export type PrivateTransaction = {
  kind: "shield" | "payroll";
  stage: "wallet" | "confirming" | "confirmed" | "failed";
  label: string;
  hash?: string;
  error?: string;
  grossAmount?: bigint;
  privacyFee?: bigint;
  netAmount?: bigint;
  balanceRefreshed?: boolean;
  balanceRefreshError?: string;
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
  shieldedBalance: bigint | null;
  publicStrkBalance: bigint | null;
  isRefreshingPublicBalance: boolean;
  publicBalanceError: string;
  privacyFee: bigint | null;
  isRefreshingPrivacyFee: boolean;
  privacyFeeError: string;
  isRefreshingBalance: boolean;
  transaction: PrivateTransaction | null;
  error: string;
  connectWallet: (name: string) => Promise<void>;
  disconnectWallet: () => Promise<void>;
  switchToMainnet: () => Promise<void>;
  refreshPublicBalance: () => Promise<bigint>;
  refreshPrivacyFee: () => Promise<bigint>;
  refreshBalance: () => Promise<void>;
  shieldStrk: (amount: string) => Promise<string>;
  runPrivatePayroll: (recipients: PayrollRecipient[]) => Promise<string>;
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
  if (typeof error === "string") return error;
  if (error && typeof error === "object") {
    const candidate = error as {
      code?: unknown;
      message?: unknown;
      data?: unknown;
      error?: { code?: unknown; message?: unknown; data?: unknown };
    };
    const message = candidate.message ?? candidate.error?.message;
    const code = candidate.code ?? candidate.error?.code;
    const data = candidate.data ?? candidate.error?.data;
    if (typeof message === "string" && (typeof code === "string" || typeof code === "number")) {
      return `${message} (${code})${typeof data === "string" ? `: ${data}` : ""}`;
    }
    if (typeof message === "string") {
      return `${message}${typeof data === "string" ? `: ${data}` : ""}`;
    }
    if (typeof code === "string" || typeof code === "number") return String(code);
  }
  if (error instanceof Error) return error.message;
  return "The wallet did not complete the request.";
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

async function readMainnetPrivacyFee(): Promise<bigint> {
  const result = await mainnetProvider.callContract({
    contractAddress: STRK20_MAINNET_POOL_ADDRESS,
    entrypoint: "get_fee_amount",
    calldata: [],
  });
  const fee = num.toBigInt(result[0] ?? "0x0");
  if (fee < 0n) throw new Error("The STRK20 pool returned an invalid privacy fee.");
  return fee;
}

async function readMainnetPublicStrkBalance(address: string): Promise<bigint> {
  const result = await mainnetProvider.callContract({
    contractAddress: STRK_TOKEN_ADDRESS,
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
  const trimmed = value.trim();
  if (!/^\d+(\.\d{0,18})?$/.test(trimmed)) {
    throw new Error("Enter a valid STRK amount with no more than 18 decimals.");
  }

  const [whole, fraction = ""] = trimmed.split(".");
  const amount = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, "0") || "0");
  if (amount <= 0n) throw new Error("Amount must be greater than zero.");
  return amount;
}

export function formatStrk(amount: bigint | null, maximumFractionDigits = 6) {
  if (amount === null) return "—";
  const whole = amount / 10n ** 18n;
  const rawFraction = (amount % 10n ** 18n).toString().padStart(18, "0");
  const fraction = rawFraction.slice(0, maximumFractionDigits).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
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
  const [isRefreshingPublicBalance, setIsRefreshingPublicBalance] = useState(false);
  const [publicBalanceError, setPublicBalanceError] = useState("");
  const [privacyFee, setPrivacyFee] = useState<bigint | null>(null);
  const [isRefreshingPrivacyFee, setIsRefreshingPrivacyFee] = useState(false);
  const [privacyFeeError, setPrivacyFeeError] = useState("");
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

  const refreshPrivacyFee = useCallback(async () => {
    setIsRefreshingPrivacyFee(true);
    setPrivacyFeeError("");
    try {
      const fee = await readMainnetPrivacyFee();
      setPrivacyFee(fee);
      return fee;
    } catch (feeError) {
      const message = describeError(feeError);
      setPrivacyFee(null);
      setPrivacyFeeError(message);
      throw new Error(message);
    } finally {
      setIsRefreshingPrivacyFee(false);
    }
  }, []);

  useEffect(() => {
    const initialRefresh = window.setTimeout(() => {
      void refreshPrivacyFee().catch(() => undefined);
    }, 0);
    const interval = window.setInterval(() => {
      void refreshPrivacyFee().catch(() => undefined);
    }, 30_000);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(interval);
    };
  }, [refreshPrivacyFee]);

  const refreshPublicBalanceForAddress = useCallback(async (walletAddress: string) => {
    setIsRefreshingPublicBalance(true);
    setPublicBalanceError("");
    try {
      const balance = await readMainnetPublicStrkBalance(walletAddress);
      setPublicStrkBalance(balance);
      return balance;
    } catch (balanceError) {
      const message = describeError(balanceError);
      setPublicStrkBalance(null);
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
    setPublicStrkBalance(null);
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
    return refreshPublicBalanceForAddress(address);
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
      const balances = await account.strk20Balances([STRK_TOKEN_ADDRESS]);
      const strkEntry = balances.find((entry) => {
        try {
          return num.toBigInt(entry.token) === num.toBigInt(STRK_TOKEN_ADDRESS);
        } catch {
          return false;
        }
      });
      const nextBalance = strkEntry ? num.toBigInt(strkEntry.balance) : 0n;
      setShieldedBalance(nextBalance);
      setPrivacyCapability(nextBalance > 0n ? "available" : "zero");
      setPrivacyMessage(
        nextBalance > 0n
          ? "Your private STRK treasury is available for payroll."
          : "Your STRK20 account is ready but its private STRK balance is zero.",
      );
    } catch (balanceError) {
      const message = describeError(balanceError);
      setShieldedBalance(null);
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
        let balanceRefreshed = false;
        let balanceRefreshError = "";
        if (walletAccount) {
          try {
            await refreshBalanceForAccount(walletAccount);
            balanceRefreshed = true;
          } catch (refreshError) {
            balanceRefreshError = describeError(refreshError);
          }
        }
        setTransaction({
          ...pending,
          stage: "confirmed",
          hash,
          balanceRefreshed,
          balanceRefreshError: balanceRefreshError || undefined,
        });
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
      kind: "shield" | "payroll",
      label: string,
      actions: STRK20_ACTION[],
      details: Pick<PrivateTransaction, "grossAmount" | "privacyFee" | "netAmount"> = {},
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

  const shieldStrk = useCallback(
    async (amount: string) => {
      const grossAmount = parseStrkAmount(amount);
      const [currentPrivacyFee, currentPublicBalance] = await Promise.all([
        refreshPrivacyFee(),
        refreshPublicBalance(),
      ]);
      if (grossAmount > currentPublicBalance) {
        throw new Error(
          `Insufficient public STRK balance. Available ${formatStrk(currentPublicBalance)} STRK; entered ${formatStrk(grossAmount)} STRK.`,
        );
      }
      if (grossAmount <= currentPrivacyFee) {
        throw new Error(
          `Enter more than ${formatStrk(currentPrivacyFee)} STRK to cover the live STRK20 privacy fee.`,
        );
      }
      const netAmount = grossAmount - currentPrivacyFee;
      return submitPrivateActions(
        "shield",
        `${formatStrk(netAmount)} STRK shielded`,
        [{ type: "deposit", token: STRK_TOKEN_ADDRESS, amount: num.toHex(grossAmount) }],
        { grossAmount, privacyFee: currentPrivacyFee, netAmount },
      );
    },
    [refreshPrivacyFee, refreshPublicBalance, submitPrivateActions],
  );

  const runPrivatePayroll = useCallback(
    async (recipients: PayrollRecipient[]) => {
      if (recipients.length === 0) throw new Error("Add at least one recipient.");
      if (recipients.length > 50) throw new Error("A payroll can contain up to 50 recipients.");

      const seenAddresses = new Set<string>();
      const actions: STRK20_ACTION[] = recipients.map((recipient, index) => {
        let parsedAddress: string;
        try {
          parsedAddress = validateAndParseAddress(recipient.address.trim());
        } catch {
          throw new Error(`Recipient ${index + 1} has an invalid Starknet address.`);
        }
        if (seenAddresses.has(parsedAddress)) {
          throw new Error(`Recipient ${index + 1} is duplicated.`);
        }
        seenAddresses.add(parsedAddress);

        const atomicAmount = parseStrkAmount(recipient.amount);
        return {
          type: "transfer",
          token: STRK_TOKEN_ADDRESS,
          amount: num.toHex(atomicAmount),
          recipient: parsedAddress,
        };
      });

      return submitPrivateActions(
        "payroll",
        `${recipients.length} private ${recipients.length === 1 ? "payment" : "payments"}`,
        actions,
      );
    },
    [submitPrivateActions],
  );

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
    shieldedBalance,
    publicStrkBalance,
    isRefreshingPublicBalance,
    publicBalanceError,
    privacyFee,
    isRefreshingPrivacyFee,
    privacyFeeError,
    isRefreshingBalance,
    transaction,
    error,
    connectWallet,
    disconnectWallet,
    switchToMainnet,
    refreshPublicBalance,
    refreshPrivacyFee,
    refreshBalance,
    shieldStrk,
    runPrivatePayroll,
    clearTransaction: () => setTransaction(null),
  };

  return <StarknetWalletContext.Provider value={value}>{children}</StarknetWalletContext.Provider>;
}

export function useStarknetWallet() {
  const context = useContext(StarknetWalletContext);
  if (!context) throw new Error("useStarknetWallet must be used within StarknetWalletProvider");
  return context;
}
