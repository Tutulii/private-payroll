"use client";

import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  ExternalLink,
  LoaderCircle,
  ShieldAlert,
  ShieldCheck,
  WalletCards,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  STARKNET_MAINNET_EXPLORER,
  type PayoPhase3ActivationResult,
  type PayoPhase3ActivationStatus,
  useStarknetWallet,
} from "@/app/starknet/starknet-wallet";
import { PAYO_PHASE3_MAINNET_DEPLOYMENT } from "@/lib/starknet/payo-phase3-deployment";

function shortAddress(value: string) {
  return `${value.slice(0, 9)}…${value.slice(-6)}`;
}

export default function Phase3ActivationPage() {
  const starknet = useStarknetWallet();
  const [status, setStatus] = useState<PayoPhase3ActivationStatus | null>(null);
  const [result, setResult] = useState<PayoPhase3ActivationResult | null>(null);
  const [checking, setChecking] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const readActivation = starknet.readPayoPhase3Activation;

  const refresh = useCallback(async () => {
    setChecking(true);
    setError("");
    try {
      setStatus(await readActivation());
    } catch (readError) {
      setError(readError instanceof Error ? readError.message : "Could not read Phase 3 Mainnet state.");
    } finally {
      setChecking(false);
    }
  }, [readActivation]);

  useEffect(() => {
    let active = true;
    void readActivation().then((nextStatus) => {
      if (active) setStatus(nextStatus);
    }).catch((readError) => {
      if (active) {
        setError(readError instanceof Error ? readError.message : "Could not read Phase 3 Mainnet state.");
      }
    }).finally(() => {
      if (active) setChecking(false);
    });
    return () => { active = false; };
  }, [readActivation]);

  const activate = async () => {
    setBusy(true);
    setError("");
    try {
      const activated = await starknet.activatePayoPhase3();
      setResult(activated);
      setStatus(activated.status);
    } catch (activationError) {
      setError(
        activationError instanceof Error
          ? activationError.message
          : "Phase 3 registry activation did not complete.",
      );
    } finally {
      setBusy(false);
    }
  };

  const connectedAdmin = starknet.isConnected && status?.walletIsAdmin;
  const ready = status?.topologyReady && status.profiles.length === 3;

  return (
    <div className="product-page deployment-operator">
      <section className="page-heading reveal reveal--one">
        <div>
          <Link className="deployment-back" href="/payroll"><ArrowLeft size={15} /> Back to payroll</Link>
          <span className="sticker sticker--blue">PHASE 3 MAINNET ACTIVATION</span>
          <h2>Turn on the verified<br /><em>private payroll profiles.</em></h2>
          <p>The contracts are already deployed. This page asks the registry administrator for one Ready signature, activates the three reviewed verifier mappings, then reads each mapping back from Mainnet.</p>
        </div>
      </section>

      <section className="deployment-grid reveal reveal--two">
        <article className="deployment-card">
          <div className="deployment-card__heading"><ShieldCheck size={20} /><div><strong>Verified topology</strong><small>Read-only checks run before Ready opens.</small></div></div>
          <ul>
            <li>Seal: <code>{shortAddress(PAYO_PHASE3_MAINNET_DEPLOYMENT.sealAddress)}</code></li>
            <li>Policy registry: <code>{shortAddress(PAYO_PHASE3_MAINNET_DEPLOYMENT.policyRegistryAddress)}</code></li>
            <li>Administrator: <code>{shortAddress(PAYO_PHASE3_MAINNET_DEPLOYMENT.adminAddress)}</code></li>
            <li>One multicall schedules only modes 0/2/3 and proof versions 2/3/4.</li>
          </ul>
        </article>

        <article className="deployment-card deployment-card--action">
          <div className="deployment-card__heading"><WalletCards size={20} /><div><strong>Ready administrator</strong><small>{starknet.isConnected ? shortAddress(starknet.address) : "Ready is not connected"}</small></div></div>
          {!starknet.isConnected && (
            <div className="deployment-wallet-list">
              {starknet.wallets.filter(({ privacyReady }) => privacyReady).map((wallet) => (
                <button className="button button--soft" type="button" key={wallet.name} disabled={busy} onClick={() => void starknet.connectWallet(wallet.name)}>{wallet.name}</button>
              ))}
            </div>
          )}
          {starknet.isConnected && !starknet.isMainnet && (
            <button className="button button--soft" type="button" disabled={busy} onClick={() => void starknet.switchToMainnet()}>Switch Ready to Mainnet</button>
          )}
          {starknet.isConnected && starknet.isMainnet && status && !status.walletIsAdmin && (
            <div className="deployment-warning"><ShieldAlert size={14} /> Connect the registry administrator shown above.</div>
          )}
          <button
            className="button button--ink"
            type="button"
            disabled={busy || checking || !ready || !connectedAdmin || status?.allActive}
            onClick={activate}
          >
            {busy
              ? <><LoaderCircle className="spin" size={16} /> {starknet.transaction?.stage === "confirming" ? "Confirming on Mainnet" : "Approve in Ready"}</>
              : status?.allActive
                ? <>Phase 3 active <CheckCircle2 size={16} /></>
                : <>Activate three profiles <ShieldCheck size={16} /></>}
          </button>
          <small className="deployment-warning"><ShieldAlert size={14} /> This is one Mainnet registry transaction. Read the three calls in Ready before approving.</small>
        </article>
      </section>

      {(checking || error || result) && (
        <section className={`deployment-progress ${error ? "deployment-progress--error" : ""}`} role={error ? "alert" : "status"}>
          {error ? <ShieldAlert size={19} /> : checking ? <LoaderCircle className="spin" size={19} /> : <CheckCircle2 size={19} />}
          <div>
            <strong>{error ? "Activation stopped" : checking ? "Reading Mainnet" : "Verifier profiles activated"}</strong>
            <span>{error || (checking ? "Checking class hashes, seal bindings, registry admin and verifier mappings." : "All three mappings were read back from the confirmed block.")}</span>
            {result && <a href={`${STARKNET_MAINNET_EXPLORER}/tx/${result.transactionHash}`} target="_blank" rel="noreferrer">Open transaction <ExternalLink size={13} /></a>}
          </div>
        </section>
      )}

      <section className="deployment-result reveal reveal--three">
        <div className="deployment-card__heading"><ShieldCheck size={21} /><div><strong>Required verifier mappings</strong><small>{status ? `Read at block ${status.blockNumber.toLocaleString()}.` : "Waiting for Mainnet."}</small></div></div>
        <div className="deployment-addresses">
          {PAYO_PHASE3_MAINNET_DEPLOYMENT.profiles.map((profile, index) => {
            const active = status?.profiles[index]?.active;
            return (
              <a key={profile.proofVersion} href={`${STARKNET_MAINNET_EXPLORER}/contract/${profile.bundleAddress}`} target="_blank" rel="noreferrer">
                <span>{profile.name} · mode {profile.mode} · v{profile.proofVersion} {active ? "· active" : "· inactive"}</span>
                <code>{profile.bundleAddress}</code>
                {active ? <CheckCircle2 size={13} /> : <ExternalLink size={13} />}
              </a>
            );
          })}
        </div>
        <button className="button button--soft" type="button" disabled={checking || busy} onClick={() => void refresh()}>{checking ? <><LoaderCircle className="spin" size={15} /> Checking</> : <>Check Mainnet again <ShieldCheck size={15} /></>}</button>
      </section>
    </div>
  );
}
