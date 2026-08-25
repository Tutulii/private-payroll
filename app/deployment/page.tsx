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
import { useEffect, useState } from "react";
import type { PayoBrowserDeploymentPackage } from "@/lib/starknet/payo-deployment-plan";
import {
  buildPolicyCatalogRoot,
  PAYO_NET_INVOICE_POLICY,
} from "@/lib/proof/input-builder";
import {
  STARKNET_MAINNET_EXPLORER,
  type PayoDeploymentProgress,
  type PayoBaselineScheduleResult,
  type PayoMainnetDeploymentResult,
  useStarknetWallet,
} from "@/app/starknet/starknet-wallet";

const CONFIRMATION = "DEPLOY PAYO MAINNET";

function shortAddress(value: string) {
  return `${value.slice(0, 9)}…${value.slice(-6)}`;
}

export default function DeploymentPage() {
  const starknet = useStarknetWallet();
  const [confirmation, setConfirmation] = useState("");
  const [progress, setProgress] = useState<PayoDeploymentProgress | null>(null);
  const [result, setResult] = useState<PayoMainnetDeploymentResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [baseline, setBaseline] = useState<PayoBaselineScheduleResult | null>(null);

  useEffect(() => {
    let active = true;
    void fetch("/api/v1/deployment-state", {
      cache: "no-store",
      headers: { accept: "application/json" },
    }).then(async (response) => {
      if (!response.ok) return;
      const payload = await response.json() as { deployment?: PayoMainnetDeploymentResult };
      if (!active || !payload.deployment) return;
      setResult(payload.deployment);
      setProgress({
        stage: "verifying",
        message: "Existing PAYO topology verified on Mainnet. Ready can activate the baseline.",
      });
      window.setTimeout(() => {
        document.getElementById("payo-baseline")?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }, 100);
    }).catch(() => {
      // The guarded deployment flow below remains available when no evidence exists yet.
    });
    return () => { active = false; };
  }, []);

  const deploy = async () => {
    setError("");
    setResult(null);
    setBusy(true);
    try {
      if (confirmation !== CONFIRMATION) {
        throw new Error(`Type ${CONFIRMATION} exactly before loading deployment artifacts.`);
      }
      const response = await fetch("/api/v1/deployment-artifacts", {
        cache: "no-store",
        headers: { accept: "application/json" },
      });
      const payload = await response.json() as PayoBrowserDeploymentPackage & {
        error?: { message?: string };
      };
      if (!response.ok) {
        throw new Error(payload.error?.message ?? "PAYO deployment artifacts are unavailable.");
      }
      const deployed = await starknet.deployPayoMainnet(payload, setProgress);
      setResult(deployed);
      window.localStorage.setItem("payo-mainnet-deployment-v1", JSON.stringify(deployed));
      setProgress({ stage: "verifying", message: "PAYO topology verified on Mainnet." });
    } catch (deploymentError) {
      setError(
        deploymentError instanceof Error
          ? deploymentError.message
          : "PAYO Mainnet deployment did not complete.",
      );
    } finally {
      setBusy(false);
    }
  };

  const scheduleBaseline = async () => {
    if (!result) return;
    setError("");
    setBusy(true);
    try {
      setProgress({ stage: "checking", message: "Computing the exact proof policy-catalog root…" });
      const policyRoot = await buildPolicyCatalogRoot([PAYO_NET_INVOICE_POLICY]);
      setProgress({ stage: "deploying", message: "Review the policy and verifier schedule in Ready…" });
      const scheduled = await starknet.schedulePayoBaseline(result.plan, policyRoot);
      setBaseline(scheduled);
      setProgress({
        stage: "verifying",
        transactionHash: scheduled.transactionHash,
        message: "Policy and verifier activated on Mainnet.",
      });
      window.localStorage.setItem("payo-mainnet-deployment-v1", JSON.stringify({
        deployment: result,
        baseline: scheduled,
      }));
    } catch (scheduleError) {
      setError(scheduleError instanceof Error ? scheduleError.message : "Baseline scheduling failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="product-page deployment-operator">
      <section className="page-heading reveal reveal--one">
        <div>
          <Link className="deployment-back" href="/payroll"><ArrowLeft size={15} /> Back to payroll</Link>
          <span className="sticker sticker--blue">GUARDED MAINNET OPERATOR</span>
          <h2>Deploy the proof layer.<br /><em>Keep payroll non-custodial.</em></h2>
          <p>This local operator hashes the rebuilt Cairo artifacts, asks Ready to simulate and approve each missing declaration, deploys the deterministic five-contract topology, then reads every binding back from Mainnet.</p>
        </div>
      </section>

      <section className="deployment-grid reveal reveal--two">
        <article className="deployment-card">
          <div className="deployment-card__heading"><ShieldCheck size={20} /><div><strong>Safety boundary</strong><small>No seed phrase or private key enters PAYO.</small></div></div>
          <ul>
            <li>Connected Ready address becomes the registry administrator and initial limited FX publisher.</li>
            <li>The Payroll Seal is permanently bound to the canonical STRK20 Mainnet pool and SN_MAIN.</li>
            <li>Every missing declaration and the deployment require visible Ready approval.</li>
            <li>Closing or rejecting a wallet prompt stops the operation without inventing evidence.</li>
          </ul>
        </article>

        <article className="deployment-card deployment-card--action">
          <div className="deployment-card__heading"><WalletCards size={20} /><div><strong>Operator wallet</strong><small>{starknet.isConnected ? shortAddress(starknet.address) : "Ready is not connected"}</small></div></div>
          {!starknet.isConnected && (
            <div className="deployment-wallet-list">
              {starknet.wallets.filter(({ privacyReady }) => privacyReady).map((wallet) => (
                <button className="button button--soft" type="button" key={wallet.name} disabled={busy} onClick={() => void starknet.connectWallet(wallet.name)}>{wallet.name}</button>
              ))}
              {starknet.discoveryReady && starknet.wallets.every(({ privacyReady }) => !privacyReady) && <p>Install or unlock Ready, then reload this page.</p>}
            </div>
          )}
          {starknet.isConnected && !starknet.isMainnet && (
            <button className="button button--soft" type="button" disabled={busy} onClick={() => void starknet.switchToMainnet()}>Switch Ready to Mainnet</button>
          )}
          {!result && <>
            <label className="deployment-confirmation">
              <span>Explicit confirmation</span>
              <input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} placeholder={CONFIRMATION} autoComplete="off" spellCheck={false} disabled={busy} />
            </label>
            <button className="button button--ink" type="button" disabled={busy || !starknet.isConnected || !starknet.isMainnet || confirmation !== CONFIRMATION} onClick={deploy}>
              {busy ? <><LoaderCircle className="spin" size={16} /> Checking Mainnet</> : <>Review &amp; deploy <ShieldCheck size={16} /></>}
            </button>
          </>}
          {result && <div className="deployment-progress"><CheckCircle2 size={18} /><div><strong>Deployment verified</strong><span>No deployment wallet request is required. Continue to baseline activation below.</span></div></div>}
          <small className="deployment-warning"><ShieldAlert size={14} /> Mainnet writes cost real fees. Verify the connected administrator address before approving.</small>
        </article>
      </section>

      {(progress || error) && (
        <section className={`deployment-progress ${error ? "deployment-progress--error" : ""}`} role={error ? "alert" : "status"}>
          {error ? <ShieldAlert size={19} /> : busy ? <LoaderCircle className="spin" size={19} /> : <CheckCircle2 size={19} />}
          <div><strong>{error ? "Deployment stopped" : progress?.stage === "verifying" && result ? "Topology verified" : "Deployment in progress"}</strong><span>{error || progress?.message}</span>{progress?.transactionHash && <a href={`${STARKNET_MAINNET_EXPLORER}/tx/${progress.transactionHash}`} target="_blank" rel="noreferrer">Open transaction <ExternalLink size={13} /></a>}</div>
        </section>
      )}

      {result && (
        <section className="deployment-result" id="payo-baseline">
          <div className="deployment-card__heading"><CheckCircle2 size={21} /><div><strong>Verified PAYO Mainnet addresses</strong><small>Read at block {result.verifiedBlockNumber.toLocaleString()}.</small></div></div>
          <div className="deployment-addresses">
            {Object.entries(result.plan.contracts).map(([name, contract]) => (
              <a key={name} href={`${STARKNET_MAINNET_EXPLORER}/contract/${contract.address}`} target="_blank" rel="noreferrer"><span>{name.replaceAll(/([A-Z])/g, " $1")}</span><code>{contract.address}</code><ExternalLink size={13} /></a>
            ))}
          </div>
          <div className="deployment-baseline">
            <div><strong>{baseline ? "Baseline active" : "Activate proof version 1"}</strong><small>{baseline ? "The canonical policy root and bundle verifier are active on Mainnet." : "The canonical policy root and bundle verifier activate immediately after Ready confirms the transaction."}</small></div>
            {baseline ? <a className="button button--soft" href={`${STARKNET_MAINNET_EXPLORER}/tx/${baseline.transactionHash}`} target="_blank" rel="noreferrer">View schedule <ExternalLink size={14} /></a> : <button className="button button--ink" type="button" disabled={busy || !starknet.isConnected || !starknet.isMainnet} onClick={scheduleBaseline}>{busy ? <><LoaderCircle className="spin" size={15} /> Continue in Ready</> : <>Schedule baseline <ShieldCheck size={15} /></>}</button>}
          </div>
        </section>
      )}
    </div>
  );
}
