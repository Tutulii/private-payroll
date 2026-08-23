"use client";

import { useConnectWallet, useLogin, usePrivy, useWallets } from "@privy-io/react-auth";
import {
  ArrowRight,
  Bot,
  Check,
  Copy,
  ExternalLink,
  KeyRound,
  Link2,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Mail,
  Plus,
  ShieldCheck,
  Sparkles,
  WalletCards,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { useAppShell } from "../ui/app-shell";

function shortAddress(address?: string) {
  if (!address) return "Not connected";
  return `${address.slice(0, 7)}…${address.slice(-5)}`;
}

export default function WalletPage() {
  const { notify } = useAppShell();
  const { ready, authenticated, user, logout } = usePrivy();
  const { login } = useLogin({
    onComplete: () => notify("Signed in with Privy"),
    onError: () => notify("Sign-in was not completed"),
  });
  const { wallets, ready: walletsReady } = useWallets();
  const { connectWallet } = useConnectWallet({
    onSuccess: ({ wallet }) => notify(`Connected ${shortAddress(wallet.address)}`),
    onError: () => notify("Wallet connection was not completed"),
  });
  const [copied, setCopied] = useState("");

  const primaryWallet = wallets[0];
  const identity = user?.email?.address ?? user?.wallet?.address ?? "Privy account";

  const copyValue = async (value: string, label: string) => {
    await navigator.clipboard?.writeText(value);
    setCopied(value);
    notify(`${label} copied`);
    window.setTimeout(() => setCopied(""), 1700);
  };

  return (
    <div className="product-page wallet-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--blue">PRIVY CONNECTION</span>
          <h2>Your wallet,<br /><em>your payday.</em></h2>
          <p>Connect a wallet to manage identity and approvals. Sensitive payroll details remain separate from the public wallet trail.</p>
        </div>
        <div className="page-heading__actions">
          {!ready ? (
            <button type="button" className="button button--soft" disabled><LoaderCircle className="spin" size={17} /> Loading Privy</button>
          ) : !authenticated ? (
            <button type="button" className="button button--ink" onClick={() => login()}><WalletCards size={17} /> Sign in & connect</button>
          ) : (
            <button type="button" className="button button--soft" onClick={() => logout()}><LogOut size={16} /> Sign out</button>
          )}
        </div>
      </section>

      <section className={`wallet-hero-card reveal reveal--two ${authenticated ? "wallet-hero-card--connected" : ""}`}>
        <div className="wallet-hero__copy">
          <div className="connection-state"><span className={authenticated ? "connection-dot connection-dot--live" : "connection-dot"} />{authenticated ? "PRIVY ACCOUNT CONNECTED" : "READY WHEN YOU ARE"}</div>
          <h3>{authenticated ? "You’re connected." : "One friendly doorway."}</h3>
          <p>{authenticated ? "Your Payo identity is ready. Connect an external wallet below to use it for supported onchain actions." : "Use a wallet or email to create your Payo identity. Privy keeps the sign-in flow simple and secure."}</p>
          {!ready ? (
            <button type="button" className="button button--ink" disabled><LoaderCircle className="spin" size={17} /> Waking up Privy</button>
          ) : !authenticated ? (
            <button type="button" className="button button--ink" onClick={() => login()}>Connect with Privy <ArrowRight size={17} /></button>
          ) : !primaryWallet ? (
            <button type="button" className="button button--ink" disabled={!walletsReady} onClick={() => connectWallet({ description: "Connect a wallet to your private payroll account", walletChainType: "ethereum-only" })}>
              <Plus size={17} /> Connect external wallet
            </button>
          ) : (
            <div className="connected-chip"><Check size={16} /><span><small>Primary wallet</small><strong>{shortAddress(primaryWallet.address)}</strong></span></div>
          )}
          <div className="wallet-trust-row"><ShieldCheck size={15} /> Powered by Privy · Payo never asks for your recovery phrase</div>
        </div>

        <div className="wallet-art" aria-hidden="true">
          <span className="wallet-art__spark wallet-art__spark--one">✦</span><span className="wallet-art__spark wallet-art__spark--two">✦</span>
          <div className="wallet-character">
            <div className="wallet-character__flap" />
            <div className="wallet-character__face"><i /><i /><b /></div>
            <span className="wallet-character__card">PAYO</span>
            <div className="wallet-character__legs"><i /><i /></div>
          </div>
          <div className="wallet-key"><KeyRound size={22} /></div>
          <div className="wallet-shield"><ShieldCheck size={24} /></div>
          <div className="wallet-art__ground" />
        </div>

        <div className="identity-card">
          <div className="identity-card__top"><span className="identity-avatar">TA</span><span><small>Payo identity</small><strong>{authenticated ? "Connected" : "Not connected"}</strong></span><i className={authenticated ? "identity-light identity-light--live" : "identity-light"} /></div>
          <div className="identity-field"><span><Mail size={14} /> Identity</span><strong>{authenticated ? identity : "Connect to view"}</strong></div>
          <div className="identity-field"><span><WalletCards size={14} /> Wallets</span><strong>{authenticated ? `${wallets.length} linked` : "—"}</strong></div>
          <div className="identity-field"><span><LockKeyhole size={14} /> Session</span><strong>{authenticated ? "Protected by Privy" : "Inactive"}</strong></div>
          <div className="identity-card__foot"><ShieldCheck size={14} /> Authentication is ready for payroll permissions</div>
        </div>
      </section>

      <section className="wallet-content-grid reveal reveal--three">
        <div className="wallet-list-card">
          <div className="wallet-section-title"><div><span className="label">CONNECTED ACCOUNTS</span><h3>Your wallets</h3></div>{authenticated && <button type="button" className="circle-add" aria-label="Connect another wallet" onClick={() => connectWallet({ description: "Add another wallet to Payo", walletChainType: "ethereum-only" })}><Plus size={18} /></button>}</div>
          {!ready || !walletsReady ? (
            <div className="wallet-empty"><LoaderCircle className="spin" size={24} /><strong>Checking your wallets…</strong></div>
          ) : wallets.length > 0 ? (
            <div className="connected-wallets">
              {wallets.map((wallet, index) => (
                <article className="connected-wallet-row" key={`${wallet.address}-${index}`}>
                  <span className={`wallet-logo wallet-logo--${index % 3}`}><WalletCards size={19} /></span>
                  <div><strong>{index === 0 ? "Primary wallet" : `Wallet ${index + 1}`}</strong><span>{shortAddress(wallet.address)}</span></div>
                  <span className="chain-pill">EVM</span>
                  <button type="button" onClick={() => copyValue(wallet.address, "Wallet address")} aria-label="Copy wallet address">{copied === wallet.address ? <Check size={15} /> : <Copy size={15} />}</button>
                </article>
              ))}
            </div>
          ) : (
            <div className="wallet-empty">
              <span className="wallet-empty__icon"><Link2 size={23} /></span>
              <strong>No external wallet yet</strong>
              <p>Sign in, then connect a supported wallet to make it available to Payo.</p>
              <button type="button" className="button button--soft" disabled={!authenticated} onClick={() => connectWallet({ description: "Connect a wallet to Payo", walletChainType: "ethereum-only" })}>Connect wallet</button>
            </div>
          )}
        </div>

        <aside className="wallet-safety-card">
          <span className="label">GOOD TO KNOW</span>
          <h3>Private payroll needs two layers.</h3>
          <div className="layer-list">
            <div><span className="layer-number">1</span><span><strong>Identity connection</strong><small>Privy signs you into Payo and connects supported external wallets.</small></span></div>
            <div><span className="layer-number layer-number--dark">2</span><span><strong>Starknet payroll signer</strong><small>STRK20 transactions require a Starknet-native wallet integration.</small></span></div>
          </div>
          <div className="tier-note"><Sparkles size={17} /><span><strong>Privy supports Starknet server wallets</strong><small>Useful for policy-controlled AI agents; these must be created securely from the backend.</small></span></div>
          <a className="docs-link" href="https://docs.privy.io/wallets/overview/chains" target="_blank" rel="noreferrer">View Privy chain support <ExternalLink size={14} /></a>
        </aside>
      </section>

      <section className="wallet-agent-strip reveal reveal--four">
        <div className="agent-access__icon"><Bot size={25} /><Zap size={12} /></div>
        <div><span className="label">FOR AI AGENTS</span><h3>Policy-controlled wallets belong on the server.</h3><p>Agent wallets can be provisioned through Privy’s server APIs with spending policies. The rotated app secret must only be used in that backend flow.</p></div>
        <button type="button" className="button button--soft" onClick={() => notify("Agent wallet setup is planned for the backend phase")}>Plan agent wallet <ArrowRight size={16} /></button>
      </section>
    </div>
  );
}
