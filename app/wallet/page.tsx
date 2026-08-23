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
  X,
  Zap,
} from "lucide-react";
import { useState } from "react";
import {
  formatStrk,
  shortStarknetAddress,
  STARKNET_SEPOLIA_EXPLORER,
  useStarknetWallet,
} from "../starknet/starknet-wallet";
import { useAppShell } from "../ui/app-shell";

function shortAddress(address?: string) {
  if (!address) return "Not connected";
  return `${address.slice(0, 7)}…${address.slice(-5)}`;
}

export default function WalletPage() {
  const { notify } = useAppShell();
  const starknet = useStarknetWallet();
  const { ready, authenticated, user } = usePrivy();
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
  const [pickerOpen, setPickerOpen] = useState(false);

  const primaryWallet = wallets[0];
  const identity = user?.email?.address ?? user?.wallet?.address ?? "Privy account";
  const privacyStatus = {
    unknown: "—",
    checking: "Checking…",
    uninitialized: "Not initialized",
    zero: "0 STRK",
    available: "Available",
    error: "Balance error",
    unsupported: "API unsupported",
  }[starknet.privacyCapability];
  const shieldTransaction = starknet.transaction?.kind === "shield" ? starknet.transaction : null;
  const shieldBusy = shieldTransaction?.stage === "wallet" || shieldTransaction?.stage === "confirming";

  const copyValue = async (value: string, label: string) => {
    await navigator.clipboard?.writeText(value);
    setCopied(value);
    notify(`${label} copied`);
    window.setTimeout(() => setCopied(""), 1700);
  };

  const connectStarknetWallet = async (name: string) => {
    try {
      await starknet.connectWallet(name);
      setPickerOpen(false);
      notify(`${name} connected on ${starknet.networkName}`);
    } catch (connectionError) {
      notify(connectionError instanceof Error ? connectionError.message : "Wallet connection failed");
    }
  };

  const refreshShieldedBalance = async () => {
    try {
      await starknet.refreshBalance();
      notify("Shielded STRK balance refreshed");
    } catch (balanceError) {
      notify(balanceError instanceof Error ? balanceError.message : "Balance check failed");
    }
  };

  const initializePrivacy = async () => {
    try {
      const hash = await starknet.shieldStrk("0.01");
      notify(`0.01 STRK shield submitted · ${hash.slice(0, 10)}…`);
    } catch (shieldError) {
      notify(shieldError instanceof Error ? shieldError.message : "Shielding was not completed");
    }
  };

  return (
    <div className="product-page wallet-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--blue">WALLETS &amp; IDENTITY</span>
          <h2>Two keys.<br /><em>One simple desk.</em></h2>
          <p>Ready signs private Starknet payroll transactions. Privy remains the friendly identity layer for humans and, later, policy-controlled agents.</p>
        </div>
        <div className="page-heading__actions">
          {!starknet.discoveryReady ? (
            <button type="button" className="button button--soft" disabled><LoaderCircle className="spin" size={17} /> Looking for Ready</button>
          ) : !starknet.isConnected ? (
            <button type="button" className="button button--ink" onClick={() => setPickerOpen(true)}><WalletCards size={17} /> Connect Ready</button>
          ) : (
            <button type="button" className="button button--soft" onClick={() => starknet.disconnectWallet()}><LogOut size={16} /> Disconnect Ready</button>
          )}
        </div>
      </section>

      <section className={`ready-wallet-card reveal reveal--two ${starknet.isConnected ? "ready-wallet-card--connected" : ""}`}>
        <div className="ready-wallet-copy">
          <div className="connection-state"><span className={starknet.isConnected ? "connection-dot connection-dot--live" : "connection-dot"} />{starknet.isConnected ? "STARKNET SIGNER CONNECTED" : "PAYROLL SIGNER"}</div>
          <span className="ready-wordmark">ready<span>.</span></span>
          <h3>{starknet.isConnected ? "Private payments are within reach." : "Connect the wallet that understands privacy."}</h3>
          <p>{starknet.isConnected ? "Payo can now ask Ready to shield STRK and approve a private payroll batch. You stay in control of every signature." : "STRK20 privacy actions use Starknet’s Wallet API. Ready supports that flow today; a normal EVM connection cannot sign it."}</p>
          <div className="ready-wallet-actions">
            {!starknet.isConnected ? (
              <button type="button" className="button button--ink" disabled={!starknet.discoveryReady || starknet.isConnecting} onClick={() => setPickerOpen(true)}>
                {starknet.isConnecting ? <><LoaderCircle className="spin" size={17} /> Waiting for wallet</> : <>Choose Starknet wallet <ArrowRight size={17} /></>}
              </button>
            ) : !starknet.isSepolia ? (
              <button type="button" className="button button--ink" onClick={() => starknet.switchToSepolia().catch((switchError) => notify(switchError instanceof Error ? switchError.message : "Network switch failed"))}>Switch to Sepolia <ArrowRight size={17} /></button>
            ) : (
              <a className="button button--ink" href="/payroll#private-payroll">Prepare private payroll <ArrowRight size={17} /></a>
            )}
            <span><ShieldCheck size={15} /> Testnet-only transaction guard is on</span>
          </div>
        </div>

        <div className="ready-account-card">
          <div className="ready-account-top">
            <span className="ready-account-icon"><WalletCards size={20} /></span>
            <span><small>Starknet account</small><strong>{starknet.isConnected ? starknet.walletName : "Not connected"}</strong></span>
            <i className={starknet.isConnected ? "identity-light identity-light--live" : "identity-light"} />
          </div>
          <div className="ready-account-balance"><small>Shielded treasury</small><strong>{formatStrk(starknet.shieldedBalance)} <span>STRK</span></strong><button type="button" disabled={!starknet.isConnected || starknet.isRefreshingBalance || starknet.privacyCapability === "unsupported"} onClick={refreshShieldedBalance}>{starknet.isRefreshingBalance ? <LoaderCircle className="spin" size={14} /> : "Refresh"}</button></div>
          <div className="ready-account-row"><span>Network</span><strong className={starknet.isSepolia ? "network-good" : "network-warn"}>{starknet.networkName}</strong></div>
          <div className="ready-account-row"><span>Wallet API</span><strong>{starknet.walletApiVersion ? `v${starknet.walletApiVersion}` : starknet.isConnected ? "Not reported" : "—"}</strong></div>
          <div className="ready-account-row"><span>Private STRK</span><strong className={`privacy-status privacy-status--${starknet.privacyCapability}`}>{privacyStatus}</strong></div>
          <div className="ready-account-row"><span>Address</span><strong>{shortStarknetAddress(starknet.address)}</strong></div>
          {starknet.isConnected && starknet.privacyMessage && <div className={`ready-inline-note ready-inline-note--${starknet.privacyCapability}`}>{starknet.privacyMessage}</div>}
          {starknet.isConnected && starknet.isSepolia && (starknet.privacyCapability === "uninitialized" || starknet.privacyCapability === "zero" || starknet.privacyCapability === "error") && (
            <button type="button" className="ready-privacy-action" disabled={shieldBusy} onClick={initializePrivacy}>
              {shieldBusy ? <><LoaderCircle className="spin" size={14} /> {shieldTransaction?.stage === "wallet" ? "Approve in Ready" : "Confirming on Sepolia"}</> : <><ShieldCheck size={14} /> {starknet.privacyCapability === "uninitialized" ? "Initialize & shield 0.01 STRK" : starknet.privacyCapability === "error" ? "Try shielding 0.01 STRK" : "Shield 0.01 STRK"}</>}
            </button>
          )}
          {shieldTransaction && (
            <div className={`ready-shield-status ready-shield-status--${shieldTransaction.stage}`}>
              <span>{shieldTransaction.stage === "confirmed" ? <Check size={14} /> : shieldTransaction.stage === "failed" ? <X size={14} /> : <LoaderCircle className="spin" size={14} />}{shieldTransaction.stage === "confirmed" ? shieldTransaction.balanceRefreshed ? "Shield confirmed · balance refreshed" : "Shield confirmed · refresh unavailable" : shieldTransaction.stage === "failed" ? "Shield failed" : shieldTransaction.stage === "wallet" ? "Waiting for Ready" : "Shield submitted"}</span>
              {shieldTransaction.hash && <a href={`${STARKNET_SEPOLIA_EXPLORER}/tx/${shieldTransaction.hash}`} target="_blank" rel="noreferrer">Receipt <ExternalLink size={12} /></a>}
            </div>
          )}
          {starknet.address && <div className="ready-account-buttons"><button type="button" onClick={() => copyValue(starknet.address, "Starknet address")}>{copied === starknet.address ? <Check size={14} /> : <Copy size={14} />} Copy</button><a href={`${STARKNET_SEPOLIA_EXPLORER}/contract/${starknet.address}`} target="_blank" rel="noreferrer">Explorer <ExternalLink size={13} /></a></div>}
          {starknet.error && <div className="ready-inline-error">{starknet.error}</div>}
        </div>
      </section>

      <section className={`wallet-hero-card reveal reveal--three ${authenticated ? "wallet-hero-card--connected" : ""}`}>
        <div className="wallet-hero__copy">
          <div className="connection-state"><span className={authenticated ? "connection-dot connection-dot--live" : "connection-dot"} />{authenticated ? "PRIVY IDENTITY CONNECTED" : "OPTIONAL IDENTITY LAYER"}</div>
          <h3>{authenticated ? "Your identity is connected." : "One friendly sign-in."}</h3>
          <p>{authenticated ? "Privy handles your Payo identity. Your Ready wallet remains the signer for all STRK20 payroll transactions." : "Use a wallet or email to create your Payo identity. This is separate from the Ready payroll signer above."}</p>
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

      <section className="wallet-content-grid reveal reveal--four">
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
            <div><span className="layer-number">1</span><span><strong>Ready payroll signer</strong><small>Approves shielding and private Starknet salary batches.</small></span></div>
            <div><span className="layer-number layer-number--dark">2</span><span><strong>Privy identity</strong><small>Signs humans into Payo and later helps provision policy-controlled agent wallets.</small></span></div>
          </div>
          <div className="tier-note"><Sparkles size={17} /><span><strong>Privy supports Starknet server wallets</strong><small>Useful for policy-controlled AI agents; these must be created securely from the backend.</small></span></div>
          <a className="docs-link" href="https://docs.privy.io/wallets/overview/chains" target="_blank" rel="noreferrer">View Privy chain support <ExternalLink size={14} /></a>
        </aside>
      </section>

      <section className="wallet-agent-strip reveal reveal--five">
        <div className="agent-access__icon"><Bot size={25} /><Zap size={12} /></div>
        <div><span className="label">FOR AI AGENTS</span><h3>Policy-controlled wallets belong on the server.</h3><p>Agent wallets can be provisioned through Privy’s server APIs with spending policies. The rotated app secret must only be used in that backend flow.</p></div>
        <button type="button" className="button button--soft" onClick={() => notify("Agent wallet setup is planned for the backend phase")}>Plan agent wallet <ArrowRight size={16} /></button>
      </section>

      {pickerOpen && (
        <div className="modal-wrap" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !starknet.isConnecting && setPickerOpen(false)}>
          <section className="wallet-picker" role="dialog" aria-modal="true" aria-labelledby="wallet-picker-title">
            <div className="wallet-picker-top"><div><span className="label">STARKNET WALLET</span><h2 id="wallet-picker-title">Choose your signer</h2></div><button type="button" className="modal-close" disabled={starknet.isConnecting} onClick={() => setPickerOpen(false)} aria-label="Close wallet picker"><X size={19} /></button></div>
            <p>Ready is recommended because it currently implements the STRK20 privacy Wallet API used by payroll.</p>
            {starknet.wallets.length > 0 ? (
              <div className="starknet-wallet-list">
                {starknet.wallets.map((wallet) => (
                  <button type="button" key={wallet.name} disabled={starknet.isConnecting || !wallet.privacyReady} onClick={() => connectStarknetWallet(wallet.name)}>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={wallet.icon} alt="" />
                    <span><strong>{wallet.name}</strong><small>{wallet.privacyReady ? "STRK20 privacy ready" : "Privacy API not available yet"}</small></span>
                    <em>{wallet.privacyReady ? (starknet.isConnecting ? "…" : "Connect →") : "Unavailable"}</em>
                  </button>
                ))}
              </div>
            ) : (
              <div className="wallet-install-card"><span className="wallet-empty__icon"><WalletCards size={23} /></span><strong>Ready is not detected</strong><p>Install the Ready browser wallet, create or import a Starknet account, then reload Payo.</p><a className="button button--ink" href="https://www.ready.co/" target="_blank" rel="noreferrer">Get Ready wallet <ExternalLink size={15} /></a></div>
            )}
            {starknet.error && <div className="wallet-picker-error">{starknet.error}</div>}
            <div className="wallet-picker-foot"><ShieldCheck size={15} /> Payo never sees your recovery phrase or STRK20 viewing key.</div>
          </section>
        </div>
      )}
    </div>
  );
}
