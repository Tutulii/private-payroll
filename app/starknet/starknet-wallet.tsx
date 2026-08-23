"use client";

import { createStore, type Store } from "@starknet-io/get-starknet-discovery";
import type { WalletWithStarknetFeatures } from "@starknet-io/get-starknet-wallet-standard/features";
import {
  constants as starknetConstants,
  num,
  RpcProvider,
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
export const STARKNET_SEPOLIA_CHAIN_ID = starknetConstants.StarknetChainId.SN_SEPOLIA;
export const STARKNET_SEPOLIA_EXPLORER = "https://sepolia.starkscan.co";

const starknetRpcUrl =
  process.env.NEXT_PUBLIC_STARKNET_RPC_URL ?? "https://api.cartridge.gg/x/starknet/sepolia";
const sepoliaProvider = new RpcProvider({ nodeUrl: starknetRpcUrl });

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
};

type StarknetWalletContextValue = {
  wallets: WalletChoice[];
  discoveryReady: boolean;
  isConnected: boolean;
  isConnecting: boolean;
  walletName: string;
  address: string;
  chainId: string;
  networkName: string;
  isSepolia: boolean;
  supportedSpecs: string[];
  privacyCapability: "unknown" | "ready" | "unsupported";
  shieldedBalance: bigint | null;
  isRefreshingBalance: boolean;
  transaction: PrivateTransaction | null;
  error: string;
  connectWallet: (name: string) => Promise<void>;
  disconnectWallet: () => Promise<void>;
  switchToSepolia: () => Promise<void>;
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
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "The wallet did not complete the request.";
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
  const [isConnecting, setIsConnecting] = useState(false);
  const [shieldedBalance, setShieldedBalance] = useState<bigint | null>(null);
  const [isRefreshingBalance, setIsRefreshingBalance] = useState(false);
  const [privacyCapability, setPrivacyCapability] = useState<"unknown" | "ready" | "unsupported">("unknown");
  const [transaction, setTransaction] = useState<PrivateTransaction | null>(null);
  const [error, setError] = useState("");
  const unsubscribeWalletRef = useRef<(() => void) | null>(null);

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

  const clearConnection = useCallback(() => {
    unsubscribeWalletRef.current?.();
    unsubscribeWalletRef.current = null;
    setWalletAccount(null);
    setSelectedWallet(null);
    setAddress("");
    setChainId("");
    setSupportedSpecs([]);
    setShieldedBalance(null);
    setPrivacyCapability("unknown");
    setTransaction(null);
  }, []);

  const refreshBalanceForAccount = useCallback(async (account: WalletAccountV6) => {
    setIsRefreshingBalance(true);
    setError("");
    try {
      const balances = await account.strk20Balances([]);
      const strkEntry = balances.find((entry) => {
        try {
          return num.toBigInt(entry.token) === num.toBigInt(STRK_TOKEN_ADDRESS);
        } catch {
          return false;
        }
      });
      setShieldedBalance(strkEntry ? num.toBigInt(strkEntry.balance) : 0n);
      setPrivacyCapability("ready");
    } catch (balanceError) {
      setPrivacyCapability("unsupported");
      const message = describeError(balanceError);
      setError(message);
      throw new Error(message);
    } finally {
      setIsRefreshingBalance(false);
    }
  }, []);

  const refreshBalance = useCallback(async () => {
    if (!walletAccount) throw new Error("Connect Ready wallet first.");
    await refreshBalanceForAccount(walletAccount);
  }, [refreshBalanceForAccount, walletAccount]);

  const connectWallet = useCallback(
    async (name: string) => {
      const wallet = discoveredWallets.find((candidate) => candidate.name === name);
      if (!wallet) throw new Error("That wallet is no longer available. Reopen the picker.");

      setError("");
      setIsConnecting(true);
      setTransaction(null);
      try {
        const account = await WalletAccountV6.connect(sepoliaProvider, wallet);
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
        const specs = await walletV6.supportedSpecs(wallet);

        unsubscribeWalletRef.current?.();
        unsubscribeWalletRef.current = account.onChange((change) => {
          if (change.accounts) {
            const nextAddress = change.accounts[0]?.address;
            if (!nextAddress) {
              clearConnection();
              return;
            }
            try {
              setAddress(validateAndParseAddress(nextAddress));
            } catch {
              setAddress(nextAddress);
            }
          }
          void walletV6.requestChainId(wallet).then((nextChainId) => setChainId(String(nextChainId)));
        });

        setWalletAccount(account);
        setSelectedWallet(wallet);
        setAddress(connectedAddress);
        setChainId(activeChainId);
        setSupportedSpecs(specs.map(String));
        setPrivacyCapability(isReadyWallet(wallet.name) ? "unknown" : "unsupported");

        if (activeChainId === STARKNET_SEPOLIA_CHAIN_ID && isReadyWallet(wallet.name)) {
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
    [clearConnection, discoveredWallets, refreshBalanceForAccount],
  );

  const disconnectWallet = useCallback(async () => {
    setError("");
    try {
      await selectedWallet?.features["standard:disconnect"].disconnect();
    } finally {
      clearConnection();
    }
  }, [clearConnection, selectedWallet]);

  const switchToSepolia = useCallback(async () => {
    if (!walletAccount) throw new Error("Connect Ready wallet first.");
    setError("");
    try {
      const switched = await walletAccount.switchStarknetChain(STARKNET_SEPOLIA_CHAIN_ID);
      if (!switched) throw new Error("Switch to Starknet Sepolia in Ready and try again.");
      setChainId(STARKNET_SEPOLIA_CHAIN_ID);
      await refreshBalanceForAccount(walletAccount);
    } catch (switchError) {
      const message = describeError(switchError);
      setError(message);
      throw new Error(message);
    }
  }, [refreshBalanceForAccount, walletAccount]);

  const confirmTransaction = useCallback(
    async (hash: string, pending: PrivateTransaction) => {
      try {
        await sepoliaProvider.waitForTransaction(hash, { retries: 400, retryInterval: 3000 });
        setTransaction({ ...pending, stage: "confirmed", hash });
        if (walletAccount) {
          try {
            await refreshBalanceForAccount(walletAccount);
          } catch {
            // A confirmed receipt remains useful even if the balance query is rejected.
          }
        }
      } catch (confirmationError) {
        setTransaction({
          ...pending,
          stage: "failed",
          hash,
          error: describeError(confirmationError),
        });
      }
    },
    [refreshBalanceForAccount, walletAccount],
  );

  const submitPrivateActions = useCallback(
    async (kind: "shield" | "payroll", label: string, actions: STRK20_ACTION[]) => {
      if (!walletAccount || !address) throw new Error("Connect Ready wallet first.");
      if (chainId !== STARKNET_SEPOLIA_CHAIN_ID) {
        throw new Error("Testing is locked to Starknet Sepolia. Switch network in Ready first.");
      }
      if (!isReadyWallet(selectedWallet?.name ?? "")) {
        throw new Error("Ready wallet is currently required for STRK20 privacy actions.");
      }

      const pending: PrivateTransaction = { kind, stage: "wallet", label };
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
        void confirmTransaction(result.transaction_hash, confirming);
        return result.transaction_hash;
      } catch (transactionError) {
        const message = describeError(transactionError);
        setTransaction({ ...pending, stage: "failed", error: message });
        setError(message);
        throw new Error(message);
      }
    },
    [address, chainId, confirmTransaction, selectedWallet?.name, walletAccount],
  );

  const shieldStrk = useCallback(
    async (amount: string) => {
      const atomicAmount = parseStrkAmount(amount);
      return submitPrivateActions("shield", `${amount} STRK shield`, [
        { type: "deposit", token: STRK_TOKEN_ADDRESS, amount: num.toHex(atomicAmount) },
      ]);
    },
    [submitPrivateActions],
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
  const isSepolia = chainId === STARKNET_SEPOLIA_CHAIN_ID;
  const networkName = !chainId
    ? "Sepolia test"
    : isSepolia
      ? "Sepolia"
      : chainId === starknetConstants.StarknetChainId.SN_MAIN
        ? "Mainnet"
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

  const value: StarknetWalletContextValue = {
    wallets,
    discoveryReady,
    isConnected,
    isConnecting,
    walletName: selectedWallet?.name ?? "",
    address,
    chainId,
    networkName,
    isSepolia,
    supportedSpecs,
    privacyCapability,
    shieldedBalance,
    isRefreshingBalance,
    transaction,
    error,
    connectWallet,
    disconnectWallet,
    switchToSepolia,
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
