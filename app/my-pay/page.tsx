"use client";

import {
  Check,
  Copy,
  Download,
  FileText,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  ShieldCheck,
  WalletCards,
  X,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useRef, useState } from "react";
import { useAppShell } from "../ui/app-shell";
import { usePayoVault } from "../vault/payo-vault";
import {
  STARKNET_MAINNET_CHAIN_ID,
  STRK20_MAINNET_POOL_ADDRESS,
  useStarknetWallet,
} from "../starknet/starknet-wallet";
import {
  createReadyReportingIdentity,
  deriveDirectStrk20ReportingIdentity,
  type PayoReportingIdentityKeyPair,
} from "@/lib/crypto/reporting-identity";
import { createPayoPublicIdentity, parsePayoJsonText, serializePayoJson } from "@/lib/client/proof-package-files";
import { createPayrollReportView, type PayrollReportView } from "@/lib/client/payroll-report-view";
import {
  openWorkerPayrollEvidenceAgainstLiveBook,
  type WorkerEvidenceRecipient,
} from "@/lib/client/worker-payroll-evidence";
import type { WorkerSourceView } from "../activity/report-results";
import { PayrollReportResultCard } from "../activity/report-results";
import styles from "./page.module.css";

const MAX_WORKER_EVIDENCE_FILE_BYTES = 24 * 1024 * 1024;

type OpenedWorkerEvidence = {
  vaultKey: string;
  view: PayrollReportView;
  source: WorkerSourceView | null;
};

function shortId(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

function downloadJson(value: unknown, filename: string): void {
  const blob = new Blob([serializePayoJson(value)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export default function MyPayPage() {
  const { notify } = useAppShell();
  const vault = usePayoVault();
  const starknet = useStarknetWallet();
  const fileInput = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState("");
  const [opened, setOpened] = useState<OpenedWorkerEvidence | null>(null);
  const [directRecipientAddress, setDirectRecipientAddress] = useState("");
  const [directViewingKey, setDirectViewingKey] = useState("");
  const [directReportingKey, setDirectReportingKey] = useState<PayoReportingIdentityKeyPair | null>(null);

  const currentVaultKey = vault.session
    ? `${vault.session.organizationId}:${vault.session.principal.principalId}`
    : "";
  const visibleResult = opened?.vaultKey === currentVaultKey ? opened : null;

  const walletIdentity = useMemo(() => {
    if (!vault.session) return null;
    try {
      return createPayoPublicIdentity(vault.session.principal);
    } catch {
      return null;
    }
  }, [vault.session]);

  const readyReportingKey = useMemo(() => {
    if (!vault.session || !starknet.address) return null;
    try {
      return createReadyReportingIdentity({
        principal: vault.session.principal,
        context: {
          chainId: STARKNET_MAINNET_CHAIN_ID,
          poolAddress: STRK20_MAINNET_POOL_ADDRESS,
          recipientAddress: starknet.address,
        },
      });
    } catch {
      return null;
    }
  }, [starknet.address, vault.session]);

  const evidenceRecipients = useMemo<WorkerEvidenceRecipient[]>(() => {
    const recipients: WorkerEvidenceRecipient[] = [];
    if (directReportingKey) {
      recipients.push({
        principal: directReportingKey.principal,
        identityFingerprint: directReportingKey.identity.fingerprint,
      });
    }
    if (vault.session) {
      recipients.push({
        principal: vault.session.principal,
        identityFingerprint: readyReportingKey?.identity.fingerprint,
      });
    }
    return recipients;
  }, [directReportingKey, readyReportingKey, vault.session]);

  const buildResultView = (
    result: Awaited<ReturnType<typeof openWorkerPayrollEvidenceAgainstLiveBook>>,
  ): OpenedWorkerEvidence => ({
    vaultKey: currentVaultKey,
    view: createPayrollReportView({
      file: result.encryptedReport,
      filename: result.reportFilename,
      recipientPrincipalId: result.recipientPrincipalId,
      payload: result.statement,
      verification: result.verification,
      blockNumber: result.snapshot.blockNumber,
      familiarTaxDocuments: result.familiarTaxDocuments,
      familiarTaxIssues: result.familiarTaxIssues,
    }),
    source: result.kind === "source" ? {
      file: result.encryptedSource,
      filename: result.sourceFilename,
      workerName: result.statement.recipientReference,
      recipientAddress: result.statement.recipientAddress,
      identityMode: result.recipientIdentity.mode,
      identityFingerprint: result.recipientIdentity.fingerprint,
      sourceCommitment: result.sourceCommitment,
    } : null,
  });

  const openEvidenceFile = async (file: File) => {
    setError("");
    setBusy(true);
    try {
      if (!vault.client || !vault.session) {
        throw new Error("Connect Ready, authorize PAYO, and unlock your vault first.");
      }
      if (file.size > MAX_WORKER_EVIDENCE_FILE_BYTES) {
        throw new Error("The encrypted worker evidence file is larger than 24 MB.");
      }
      const value = parsePayoJsonText(await file.text(), "The encrypted worker evidence file");
      const result = await openWorkerPayrollEvidenceAgainstLiveBook({
        client: vault.client,
        value,
        sourceFilename: file.name,
        recipients: evidenceRecipients,
      });
      const next = buildResultView(result);
      setOpened(next);
      if (result.kind === "source") {
        downloadJson(result.encryptedReport, result.reportFilename);
        notify("Your encrypted statement was generated and checked against the live payroll book");
      } else {
        notify("Your encrypted statement was opened and checked against the live payroll book");
      }
    } catch (openError) {
      setOpened(null);
      setError(openError instanceof Error
        ? openError.message
        : "The encrypted worker evidence could not be opened.");
    } finally {
      setBusy(false);
    }
  };

  const deriveDirectKey = () => {
    setError("");
    try {
      const recipientAddress = directRecipientAddress.trim() || starknet.address;
      if (!recipientAddress) throw new Error("Enter the direct STRK20 recipient address.");
      if (!directViewingKey.trim()) throw new Error("Enter the direct STRK20 viewing key.");
      const keyPair = deriveDirectStrk20ReportingIdentity({
        viewingKey: directViewingKey.trim(),
        context: {
          chainId: STARKNET_MAINNET_CHAIN_ID,
          poolAddress: STRK20_MAINNET_POOL_ADDRESS,
          recipientAddress,
        },
      });
      setDirectReportingKey(keyPair);
      notify("Direct reporting key derived locally for this browser session");
    } catch (derivationError) {
      setDirectReportingKey(null);
      setError(derivationError instanceof Error
        ? derivationError.message
        : "The direct reporting key could not be derived.");
    } finally {
      setDirectViewingKey("");
    }
  };

  const reverify = async () => {
    if (!visibleResult || !vault.client || !vault.session) return;
    setError("");
    setBusy(true);
    try {
      const result = await openWorkerPayrollEvidenceAgainstLiveBook({
        client: vault.client,
        value: visibleResult.view.file,
        sourceFilename: visibleResult.view.filename,
        recipients: evidenceRecipients,
      });
      const next = buildResultView(result);
      setOpened({ ...next, source: visibleResult.source ?? next.source });
      notify("Live payroll-book root checked again");
    } catch (recheckError) {
      setError(recheckError instanceof Error
        ? recheckError.message
        : "The live payroll-book check could not be repeated.");
    } finally {
      setBusy(false);
    }
  };

  const copyCommitment = async (value: string) => {
    await navigator.clipboard?.writeText(value);
    notify("Evidence commitment copied");
  };

  const lockedAction = !starknet.isConnected
    ? { href: "/wallet", label: "Connect Ready" }
    : !starknet.isMainnet
      ? { href: "/wallet", label: "Switch to Mainnet" }
      : !vault.authenticated
        ? { href: "/wallet", label: "Authorize PAYO" }
        : { href: "/payroll#private-payroll", label: "Unlock PAYO vault" };

  return (
    <div className={`product-page ${styles.page}`}>
      <section className={`${styles.hero} reveal reveal--one`}>
        <div>
          <span className="sticker sticker--blue">EMPLOYEE SELF-SERVICE</span>
          <h2>Your pay evidence.<br /><em>Opened only by you.</em></h2>
          <p>Open an encrypted worker source or income statement. PAYO decrypts it in this browser and checks it against the live Mainnet payroll book before showing any pay details.</p>
        </div>
        <div className={styles.heroSeal} aria-hidden="true"><FileText size={34} /><span><ShieldCheck size={16} /></span></div>
      </section>

      <section className={styles.trustStrip} aria-label="Privacy guarantees">
        <span><LockKeyhole size={16} /> Local decryption</span>
        <span><ShieldCheck size={16} /> Live-book verification</span>
        <span><WalletCards size={16} /> No transaction or fee</span>
      </section>

      {!vault.session ? (
        <section className={`${styles.locked} reveal reveal--two`}>
          <span className={styles.lockedIcon}><KeyRound size={24} /></span>
          <div><small>MY PAY IS LOCKED</small><h3>Open your own PAYO vault</h3><p>Use the Ready wallet that received this payroll. Authorize PAYO and unlock the matching vault before choosing the encrypted file.</p></div>
          <Link className="button button--ink" href={lockedAction.href}>{lockedAction.label}</Link>
        </section>
      ) : (
        <>
          <section className={`${styles.identity} reveal reveal--two`} aria-label="Worker identity status">
            <span className={styles.identityIcon}><ShieldCheck size={21} /></span>
            <div><small>WALLET-BOUND ENCRYPTION IDENTITY</small><strong>Matching PAYO vault ready</strong><p>{walletIdentity ? `Fingerprint ${shortId(walletIdentity.fingerprint)}` : "The unlocked vault key remains only in this browser session."}</p></div>
            <span className={styles.readyBadge}><Check size={14} /> Ready</span>
          </section>

          <section className={`${styles.openCard} reveal reveal--three`}>
            <div className={styles.openIntro}>
              <span className="label">OPEN MY ENCRYPTED STATEMENT</span>
              <h3>Choose the file your employer sent you</h3>
              <p>Accepted: a PAYO encrypted worker statement source or a final worker income statement. Complete employer and reviewer books are refused here.</p>
            </div>
            <div
              className={`${styles.dropzone} ${dragActive ? styles.dropzoneActive : ""}`}
              aria-busy={busy}
              onDragEnter={(event) => { event.preventDefault(); setDragActive(true); }}
              onDragOver={(event) => event.preventDefault()}
              onDragLeave={(event) => { if (event.currentTarget === event.target) setDragActive(false); }}
              onDrop={(event) => {
                event.preventDefault();
                setDragActive(false);
                const file = event.dataTransfer.files[0];
                if (file) void openEvidenceFile(file);
              }}
            >
              <span><Download size={25} /></span>
              <div><strong>{busy ? "Checking encrypted evidence…" : "Drop the encrypted JSON here"}</strong><p>The file stays in this browser. PAYO sends only the public checkpoint query needed for verification.</p></div>
              <button type="button" className="button button--ink" disabled={busy} onClick={() => fileInput.current?.click()}>{busy ? <LoaderCircle className="spin" size={17} /> : <FileText size={17} />} {busy ? "Checking" : "Choose encrypted file"}</button>
              <input
                ref={fileInput}
                className={styles.hiddenInput}
                type="file"
                accept="application/json,.json"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  if (file) void openEvidenceFile(file);
                }}
                tabIndex={-1}
                aria-hidden="true"
              />
            </div>
            <p className={styles.filingNotice}><ShieldCheck size={15} /><span>This is encrypted supporting evidence for your records. It does not submit an official W-2, P60, T4 or government tax return.</span></p>
          </section>

          <details className={`${styles.directTools} reveal reveal--four`}>
            <summary><span><KeyRound size={17} /> Direct STRK20 recipient</span><small>Advanced fallback</small></summary>
            <div>
              <p>Use this only when the employer encrypted the source to a report-only identity derived from your direct STRK20 viewing key. The viewing key stays in memory, is cleared after derivation, and is never uploaded. Never enter a recovery phrase.</p>
              <div className={styles.directFields}>
                <label><span>Private recipient address</span><input value={directRecipientAddress} onChange={(event) => setDirectRecipientAddress(event.target.value)} placeholder={starknet.address || "0x…"} autoComplete="off" spellCheck={false} /></label>
                <label><span>Direct viewing key</span><input type="password" value={directViewingKey} onChange={(event) => setDirectViewingKey(event.target.value)} placeholder="Never use a recovery phrase" autoComplete="off" spellCheck={false} /></label>
                <button type="button" className="button button--soft" onClick={deriveDirectKey} disabled={!directViewingKey.trim()}><KeyRound size={16} /> Derive locally</button>
              </div>
              {directReportingKey && <div className={styles.directReady}><ShieldCheck size={16} /><span><strong>Direct reporting key ready</strong><small>{shortId(directReportingKey.identity.fingerprint)}</small></span><button type="button" onClick={() => setDirectReportingKey(null)} aria-label="Clear direct reporting key"><X size={15} /></button></div>}
            </div>
          </details>

          {error && <p className={styles.error} role="alert"><LockKeyhole size={17} /><span><strong>Statement not opened</strong>{error}</span></p>}

          {visibleResult?.source && <section className={styles.sourceReceipt} data-report-result="worker-source" aria-label="Verified worker source">
            <div className={styles.sourceReceiptHeader}>
              <span><FileText size={20} /></span>
              <div><small>ENCRYPTED SOURCE ACCEPTED</small><h3>{visibleResult.source.workerName}</h3><p>Identity and source verified</p></div>
              <ShieldCheck size={20} />
            </div>
            <dl className={styles.sourceFacts}>
              <div><dt>Recipient</dt><dd>{visibleResult.source.recipientAddress}</dd></div>
              <div><dt>Identity method</dt><dd>{visibleResult.source.identityMode === "direct_strk20_viewing_key" ? "Direct STRK20 reporting key" : "Ready PAYO X25519"}</dd></div>
              <div><dt>Fingerprint</dt><dd>{visibleResult.source.identityFingerprint}</dd></div>
              <div><dt>Source commitment</dt><dd>{visibleResult.source.sourceCommitment}</dd></div>
            </dl>
            <div className={styles.sourceActions}>
              <button type="button" onClick={() => downloadJson(visibleResult.source!.file, visibleResult.source!.filename)}><Download size={16} /> Download encrypted source</button>
              <button type="button" onClick={() => void copyCommitment(visibleResult.source!.sourceCommitment)}><Copy size={16} /> Copy commitment</button>
            </div>
          </section>}
          {visibleResult && <PayrollReportResultCard
            view={visibleResult.view}
            busy={busy}
            canReverify={evidenceRecipients.some(({ principal }) =>
              principal.principalId === visibleResult.view.recipientPrincipalId)}
            download={downloadJson}
            reverify={() => void reverify()}
            copy={(value) => void copyCommitment(value)}
            workerHomeLabel="My Pay"
          />}
          {visibleResult && <p className={styles.downloadHint}><Download size={15} /> If you opened a worker source, the final encrypted statement downloaded automatically. Keep it with the source for future verification.</p>}
        </>
      )}
    </div>
  );
}
