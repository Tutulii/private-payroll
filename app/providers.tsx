"use client";

import { StarknetWalletProvider } from "./starknet/starknet-wallet";
import { PayoVaultProvider } from "./vault/payo-vault";

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <StarknetWalletProvider>
      <PayoVaultProvider>{children}</PayoVaultProvider>
    </StarknetWalletProvider>
  );
}
