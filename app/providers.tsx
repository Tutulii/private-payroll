"use client";

import { PrivyProvider } from "@privy-io/react-auth";
import { StarknetWalletProvider } from "./starknet/starknet-wallet";
import { PayoVaultProvider, PayoVaultUnavailableProvider } from "./vault/payo-vault";

const privyAppId = process.env.NEXT_PUBLIC_PRIVY_APP_ID;

export default function Providers({ children }: { children: React.ReactNode }) {
  const content = <StarknetWalletProvider>{children}</StarknetWalletProvider>;

  if (!privyAppId) {
    return <PayoVaultUnavailableProvider>{content}</PayoVaultUnavailableProvider>;
  }

  return (
    <PrivyProvider
      appId={privyAppId}
      config={{
        loginMethods: ["wallet", "email"],
        appearance: {
          theme: "light",
          accentColor: "#20201e",
          showWalletLoginFirst: true,
          walletChainType: "ethereum-only",
        },
      }}
    >
      <PayoVaultProvider>{content}</PayoVaultProvider>
    </PrivyProvider>
  );
}
