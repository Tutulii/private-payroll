"use client";

import {
  ArrowRight,
  Bot,
  Check,
  Copy,
  ExternalLink,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  ShieldCheck,
  Sparkles,
  WalletCards,
  X,
  Zap,
} from "lucide-react";
import { useState } from "react";
import {
  formatStrk,
  formatTokenAmount,
  shortStarknetAddress,
  STARKNET_MAINNET_EXPLORER,
  STRK20_SETUP_URL,
  useStarknetWallet,
} from "../starknet/starknet-wallet";
import { useAppShell } from "../ui/app-shell";
import { usePayoVault } from "../vault/payo-vault";

export default function WalletPage() {
  const { notify } = useAppShell();
  const starknet = useStarknetWallet();
  const vault = usePayoVault();
  const [copied, setCopied] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);

  const privacyStatus = {
    unknown: "—",
    checking: "Checking…",
    uninitialized: "Not initialized",
    zero: "0 private funds",
    available: "Available",
    error: "Balance error",
    unsupported: "API unsupported",
  }[starknet.privacyCapability];
  const shieldTransaction = starknet.transaction?.kind === "shield" ? starknet.transaction : null;

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
      notify(`${name} connected`);
    } catch (connectionError) {
      notify(connectionError instanceof Error ? connectionError.message : "Wallet connection failed");
    }
  };

  const authorizePayo = async () => {
    try {
      await vault.login();
      notify("PAYO session authorized by Ready");
    } catch (authenticationError) {
      notify(authenticationError instanceof Error ? authenticationError.message : "PAYO authorization failed");
    }
  };

  const disconnectReady = async () => {
    try {
      if (vault.authenticated) await vault.logout();
    } finally {
      await starknet.disconnectWallet();
    }
  };

  const refreshShieldedBalance = async () => {
    try {
      await Promise.all([starknet.refreshBalance(), starknet.refreshPublicBalance()]);
      notify("Public and shielded STRK/USDC balances refreshed");
    } catch (balanceError) {
      notify(balanceError instanceof Error ? balanceError.message : "Balance check failed");
    }
  };

  return (
    <div className="product-page wallet-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--blue">READY WALLET &amp; IDENTITY</span>
          <h2>One wallet.<br /><em>One private desk.</em></h2>
          <p>Ready is both your PAYO identity and the signer for private Starknet payroll. There is no separate Privy login.</p>
        </div>
        <div className="page-heading__actions">
          {!starknet.discoveryReady ? (
            <button type="button" className="button button--soft" disabled><LoaderCircle className="spin" size={17} /> Looking for Ready</button>
          ) : !starknet.isConnected ? (
            <button type="button" className="button button--ink" onClick={() => setPickerOpen(true)}><WalletCards size={17} /> Connect Ready</button>
          ) : (
            <button type="button" className="button button--soft" onClick={() => void disconnectReady()}><LogOut size={16} /> Disconnect Ready</button>
          )}
        </div>
      </section>

      <section className={`ready-wallet-card reveal reveal--two ${starknet.isConnected ? "ready-wallet-card--connected" : ""}`}>
        <div className="ready-wallet-copy">
          <div className="connection-state"><span className={starknet.isConnected ? "connection-dot connection-dot--live" : "connection-dot"} />{starknet.isConnected ? "STARKNET SIGNER CONNECTED" : "PAYROLL SIGNER"}</div>
          <span className="ready-wordmark">ready<span>.</span></span>
          <h3>{starknet.isConnected ? "Private payments are within reach." : "Connect the wallet that understands privacy."}</h3>
          <p>{starknet.isConnected ? "PAYO can ask Ready to authenticate the encrypted workspace, shield STRK or USDC, and approve a private payroll batch. Every signature stays under your control." : "STRK20 privacy actions use Starknet’s Wallet API. Ready supports that flow today; an EVM wallet cannot sign it."}</p>
          <div className="ready-wallet-actions">
            {!starknet.isConnected ? (
              <button type="button" className="button button--ink" disabled={!starknet.discoveryReady || starknet.isConnecting} onClick={() => setPickerOpen(true)}>
                {starknet.isConnecting ? <><LoaderCircle className="spin" size={17} /> Waiting for wallet</> : <>Choose Ready wallet <ArrowRight size={17} /></>}
              </button>
            ) : !starknet.isMainnet ? (
              <button type="button" className="button button--ink" onClick={() => starknet.switchToMainnet().catch((switchError) => notify(switchError instanceof Error ? switchError.message : "Network switch failed"))}>Switch to Mainnet <ArrowRight size={17} /></button>
            ) : !vault.authenticated ? (
              <button type="button" className="button button--ink" disabled={vault.loading} onClick={() => void authorizePayo()}>{vault.loading ? <><LoaderCircle className="spin" size={17} /> Waiting for Ready</> : <><KeyRound size={17} /> Authorize PAYO session</>}</button>
            ) : (
              <a className="button button--ink" href="/payroll#private-payroll">Prepare private payroll <ArrowRight size={17} /></a>
            )}
            <span><ShieldCheck size={15} /> Mainnet transaction guard is on · real STRK and USDC</span>
          </div>
        </div>

        <div className="ready-account-card">
          <div className="ready-account-top">
            <span className="ready-account-icon"><WalletCards size={20} /></span>
            <span><small>Starknet account</small><strong>{starknet.isConnected ? starknet.walletName : "Not connected"}</strong></span>
            <i className={starknet.isConnected ? "identity-light identity-light--live" : "identity-light"} />
          </div>
          <div className="ready-account-balance"><small>Shielded treasury</small><strong>{formatTokenAmount(starknet.shieldedBalances.STRK, "STRK")} <span>STRK</span><em> · </em>{formatTokenAmount(starknet.shieldedBalances.USDC, "USDC")} <span>USDC</span></strong><button type="button" disabled={!starknet.isConnected || starknet.isRefreshingBalance || starknet.privacyCapability === "unsupported"} onClick={refreshShieldedBalance}>{starknet.isRefreshingBalance ? <LoaderCircle className="spin" size={14} /> : "Refresh"}</button></div>
          <div className="ready-account-row"><span>Network</span><strong className={starknet.isMainnet ? "network-good" : "network-warn"}>{starknet.networkName}</strong></div>
          <div className="ready-account-row"><span>Wallet API</span><strong>{starknet.walletApiVersion ? `v${starknet.walletApiVersion}` : starknet.isConnected ? "Not reported" : "—"}</strong></div>
          <div className="ready-account-row"><span>Public STRK</span><strong>{formatStrk(starknet.publicStrkBalance)} STRK</strong></div>
          <div className="ready-account-row"><span>Public USDC</span><strong>{formatTokenAmount(starknet.publicBalances.USDC, "USDC")} USDC</strong></div>
          <div className="ready-account-row"><span>Private balances</span><strong className={`privacy-status privacy-status--${starknet.privacyCapability}`}>{privacyStatus}</strong></div>
          <div className="ready-account-row"><span>Address</span><strong>{shortStarknetAddress(starknet.address)}</strong></div>
          {starknet.isConnected && starknet.privacyMessage && <div className={`ready-inline-note ready-inline-note--${starknet.privacyCapability}`}>{starknet.privacyMessage}</div>}
          {starknet.isConnected && starknet.isMainnet && starknet.privacyCapability === "uninitialized" && <a className="ready-privacy-action" href={STRK20_SETUP_URL} target="_blank" rel="noreferrer"><KeyRound size={14} /> Open one-time STRK20 setup <ExternalLink size={12} /></a>}
          {starknet.isConnected && starknet.isMainnet && (starknet.privacyCapability === "zero" || starknet.privacyCapability === "available") && <a className="ready-privacy-action" href="/payroll#private-payroll"><ShieldCheck size={14} /> {starknet.privacyCapability === "zero" ? "Create live shield quote" : "Shield STRK or USDC"}</a>}
          {starknet.isConnected && starknet.isMainnet && starknet.privacyCapability === "error" && <button type="button" className="ready-privacy-action" disabled={starknet.isRefreshingBalance} onClick={refreshShieldedBalance}>{starknet.isRefreshingBalance ? <><LoaderCircle className="spin" size={14} /> Checking Ready</> : <><LoaderCircle size={14} /> Retry private balance</>}</button>}
          {shieldTransaction && <div className={`ready-shield-status ready-shield-status--${shieldTransaction.stage}`}><span>{shieldTransaction.stage === "confirmed" ? <Check size={14} /> : shieldTransaction.stage === "failed" ? <X size={14} /> : <LoaderCircle className="spin" size={14} />}{shieldTransaction.stage === "confirmed" ? shieldTransaction.balanceRefreshed ? "Shield confirmed · balance refreshed" : "Shield confirmed · refresh unavailable" : shieldTransaction.stage === "failed" ? "Shield failed" : shieldTransaction.stage === "wallet" ? "Waiting for Ready" : "Shield submitted"}</span>{shieldTransaction.hash && <a href={`${STARKNET_MAINNET_EXPLORER}/tx/${shieldTransaction.hash}`} target="_blank" rel="noreferrer">Receipt <ExternalLink size={12} /></a>}</div>}
          {starknet.address && <div className="ready-account-buttons"><button type="button" onClick={() => copyValue(starknet.address, "Starknet address")}>{copied === starknet.address ? <Check size={14} /> : <Copy size={14} />} Copy</button><a href={`${STARKNET_MAINNET_EXPLORER}/contract/${starknet.address}`} target="_blank" rel="noreferrer">Explorer <ExternalLink size={13} /></a></div>}
          {starknet.error && <div className="ready-inline-error">{starknet.error}</div>}
        </div>
      </section>

      <section className={`wallet-hero-card reveal reveal--three ${vault.authenticated ? "wallet-hero-card--connected" : ""}`}>
        <div className="wallet-hero__copy">
          <div className="connection-state"><span className={vault.authenticated ? "connection-dot connection-dot--live" : "connection-dot"} />{vault.authenticated ? "PAYO SESSION ACTIVE" : "READY AUTHENTICATION"}</div>
          <h3>{vault.authenticated ? "Your private desk is authorized." : "One clear signature."}</h3>
          <p>{vault.authenticated ? "This Ready-authorized session can access only the encrypted PAYO records assigned to your identity. Private transactions still require their own explicit approval." : "Sign typed data once to open the encrypted workspace. This does not move funds, approve tokens, or submit a transaction."}</p>
          {!starknet.isConnected ? (
            <button type="button" className="button button--ink" onClick={() => setPickerOpen(true)}>Connect Ready <ArrowRight size={17} /></button>
          ) : !starknet.isMainnet ? (
            <button type="button" className="button button--ink" onClick={() => void starknet.switchToMainnet()}>Switch to Mainnet</button>
          ) : !vault.authenticated ? (
            <button type="button" className="button button--ink" disabled={vault.loading} onClick={() => void authorizePayo()}>{vault.loading ? <><LoaderCircle className="spin" size={17} /> Authorizing</> : <>Authorize with Ready <ArrowRight size={17} /></>}</button>
          ) : (
            <div className="connected-chip"><Check size={16} /><span><small>Ready identity</small><strong>{shortStarknetAddress(starknet.address)}</strong></span></div>
          )}
          <div className="wallet-trust-row"><ShieldCheck size={15} /> PAYO never asks for your recovery phrase or STRK20 viewing key</div>
          {vault.error && <div className="ready-inline-error">{vault.error}</div>}
        </div>

        <div className="wallet-art" aria-hidden="true">
          <span className="wallet-art__spark wallet-art__spark--one">✦</span><span className="wallet-art__spark wallet-art__spark--two">✦</span>
          <div className="wallet-character"><div className="wallet-character__flap" /><div className="wallet-character__face"><i /><i /><b /></div><span className="wallet-character__card">PAYO</span><div className="wallet-character__legs"><i /><i /></div></div>
          <div className="wallet-key"><KeyRound size={22} /></div><div className="wallet-shield"><ShieldCheck size={24} /></div><div className="wallet-art__ground" />
        </div>

        <div className="identity-card">
          <div className="identity-card__top"><span className="identity-avatar">R</span><span><small>PAYO identity</small><strong>{vault.authenticated ? "Authorized" : "Locked"}</strong></span><i className={vault.authenticated ? "identity-light identity-light--live" : "identity-light"} /></div>
          <div className="identity-field"><span><WalletCards size={14} /> Signer</span><strong>{starknet.isConnected ? shortStarknetAddress(starknet.address) : "Not connected"}</strong></div>
          <div className="identity-field"><span><LockKeyhole size={14} /> Session</span><strong>{vault.authenticated ? "Ready signed" : "Inactive"}</strong></div>
          <div className="identity-field"><span><KeyRound size={14} /> Expires</span><strong>{vault.sessionExpiresAt ? new Date(vault.sessionExpiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}</strong></div>
          <div className="identity-card__foot"><ShieldCheck size={14} /> Revocable session · no transaction authority</div>
        </div>
      </section>

      <section className="wallet-content-grid reveal reveal--four">
        <div className="wallet-list-card">
          <div className="wallet-section-title"><div><span className="label">CONNECTED ACCOUNT</span><h3>Your Ready signer</h3></div></div>
          {starknet.isConnected ? (
            <div className="connected-wallets"><article className="connected-wallet-row"><span className="wallet-logo wallet-logo--0"><WalletCards size={19} /></span><div><strong>{starknet.walletName}</strong><span>{shortStarknetAddress(starknet.address)}</span></div><span className="chain-pill">STARKNET</span><button type="button" onClick={() => copyValue(starknet.address, "Wallet address")} aria-label="Copy wallet address">{copied === starknet.address ? <Check size={15} /> : <Copy size={15} />}</button></article></div>
          ) : (
            <div className="wallet-empty"><span className="wallet-empty__icon"><WalletCards size={23} /></span><strong>No Ready wallet connected</strong><p>Connect Ready to authenticate PAYO and approve private Mainnet payroll.</p><button type="button" className="button button--soft" onClick={() => setPickerOpen(true)}>Connect Ready</button></div>
          )}
        </div>

        <aside className="wallet-safety-card">
          <span className="label">GOOD TO KNOW</span>
          <h3>One wallet, separated powers.</h3>
          <div className="layer-list">
            <div><span className="layer-number">1</span><span><strong>Session signature</strong><small>Authenticates encrypted API access. It cannot move funds.</small></span></div>
            <div><span className="layer-number layer-number--dark">2</span><span><strong>Transaction approval</strong><small>Ready asks again before shielding, registry changes, or private payroll.</small></span></div>
          </div>
          <div className="tier-note"><Sparkles size={17} /><span><strong>Existing workspaces stay recoverable</strong><small>Your encrypted recovery file can prove ownership and link this Ready account without exposing its key.</small></span></div>
        </aside>
      </section>

      <section className="wallet-agent-strip reveal reveal--five">
        <div className="agent-access__icon"><Bot size={25} /><Zap size={12} /></div>
        <div><span className="label">FOR AI AGENTS</span><h3>Agents use scoped capabilities, not your wallet session.</h3><p>The MCP path receives explicit organization permissions, limits, expiry, and replay protection. Human Ready authorization remains separate.</p></div>
        <a className="button button--soft" href="/team">Review principals <ArrowRight size={16} /></a>
      </section>

      {pickerOpen && (
        <div className="modal-wrap" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !starknet.isConnecting && setPickerOpen(false)}>
          <section className="wallet-picker" role="dialog" aria-modal="true" aria-labelledby="wallet-picker-title">
            <div className="wallet-picker-top"><div><span className="label">STARKNET WALLET</span><h2 id="wallet-picker-title">Choose your signer</h2></div><button type="button" className="modal-close" disabled={starknet.isConnecting} onClick={() => setPickerOpen(false)} aria-label="Close wallet picker"><X size={19} /></button></div>
            <p>Ready is required because it implements the STRK20 privacy Wallet API used by payroll.</p>
            {starknet.wallets.length > 0 ? (
              <div className="starknet-wallet-list">{starknet.wallets.map((wallet) => <button type="button" key={wallet.name} disabled={starknet.isConnecting || !wallet.privacyReady} onClick={() => void connectStarknetWallet(wallet.name)}>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={wallet.icon} alt="" />
                <span><strong>{wallet.name}</strong><small>{wallet.privacyReady ? "STRK20 privacy ready" : "Privacy API not available"}</small></span><em>{wallet.privacyReady ? (starknet.isConnecting ? "…" : "Connect →") : "Unavailable"}</em>
              </button>)}</div>
            ) : (
              <div className="wallet-install-card"><span className="wallet-empty__icon"><WalletCards size={23} /></span><strong>Ready is not detected</strong><p>Install Ready, create or import a Starknet account, then reload PAYO.</p><a className="button button--ink" href="https://www.ready.co/" target="_blank" rel="noreferrer">Get Ready wallet <ExternalLink size={15} /></a></div>
            )}
            {starknet.error && <div className="wallet-picker-error">{starknet.error}</div>}
            <div className="wallet-picker-foot"><ShieldCheck size={15} /> PAYO never sees your recovery phrase or STRK20 viewing key.</div>
          </section>
        </div>
      )}
    </div>
  );
}
