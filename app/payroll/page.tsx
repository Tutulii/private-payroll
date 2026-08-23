"use client";

import {
  ArrowRight,
  CalendarDays,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Download,
  ExternalLink,
  LoaderCircle,
  MoreHorizontal,
  PencilLine,
  Play,
  Plus,
  ShieldCheck,
  Sparkles,
  Users,
  WalletCards,
  X,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import {
  formatStrk,
  formatTokenAmount,
  parseTokenAmount,
  PAYROLL_TOKENS,
  shortStarknetAddress,
  STARKNET_MAINNET_EXPLORER,
  STRK20_SETUP_URL,
  type PayrollTokenSymbol,
  useStarknetWallet,
} from "../starknet/starknet-wallet";
import { useAppShell } from "../ui/app-shell";

type PayrollStatus = "Ready" | "Completed" | "Draft";

const runs: Array<{
  month: string;
  detail: string;
  recipients: string;
  amount: string;
  status: PayrollStatus;
  tone: string;
}> = [
  { month: "August 2026", detail: "Scheduled for Aug 27", recipients: "12 people · 4 agents", amount: "$12,640", status: "Ready", tone: "coral" },
  { month: "July 2026", detail: "Paid Jul 28", recipients: "11 people · 4 agents", amount: "$12,210", status: "Completed", tone: "blue" },
  { month: "June 2026", detail: "Paid Jun 27", recipients: "10 people · 3 agents", amount: "$11,480", status: "Completed", tone: "green" },
  { month: "Launch sprint", detail: "Last edited Aug 20", recipients: "3 contractors", amount: "$1,850", status: "Draft", tone: "yellow" },
];

const filters = ["All", "Ready", "Completed", "Draft"] as const;

type DraftRecipient = {
  id: number;
  name: string;
  address: string;
  amount: string;
  token: PayrollTokenSymbol;
};

const firstRecipient: DraftRecipient = {
  id: 1,
  name: "",
  address: "",
  amount: "0.001",
  token: "STRK",
};

export default function PayrollPage() {
  const { openPayroll, notify } = useAppShell();
  const starknet = useStarknetWallet();
  const [filter, setFilter] = useState<(typeof filters)[number]>("All");
  const [shieldToken, setShieldToken] = useState<PayrollTokenSymbol>("STRK");
  const [shieldAmount, setShieldAmount] = useState("");
  const [recipients, setRecipients] = useState<DraftRecipient[]>([firstRecipient]);
  const [formError, setFormError] = useState("");
  const [nextRecipientId, setNextRecipientId] = useState(2);

  const visibleRuns = filter === "All" ? runs : runs.filter((run) => run.status === filter);
  const busy = starknet.transaction?.stage === "wallet" || starknet.transaction?.stage === "confirming";
  const privacyChecking = starknet.privacyCapability === "checking";
  const privacyUnsupported = starknet.privacyCapability === "unsupported";
  const registrationRequired = starknet.privacyCapability === "uninitialized";
  const balanceUnavailable = starknet.privacyCapability === "error";
  const canRunPayroll = starknet.privacyCapability === "available";
  const treasuryLabel = starknet.privacyCapability === "uninitialized"
    ? "Not initialized"
    : privacyUnsupported
      ? "API unsupported"
      : privacyChecking
        ? "Checking…"
        : starknet.privacyCapability === "error"
          ? "Balance unavailable"
          : `${formatTokenAmount(starknet.shieldedBalances.STRK, "STRK")} STRK · ${formatTokenAmount(starknet.shieldedBalances.USDC, "USDC")} USDC`;
  const treasuryHelp = starknet.privacyCapability === "uninitialized"
    ? "Complete the one-time STRK20 registration first. Wallet API 0.10.3 cannot register an account from this dapp."
    : privacyUnsupported
      ? "Update Ready to a STRK20-compatible Wallet API, then reconnect."
      : starknet.privacyCapability === "zero"
        ? "The private account is ready. Shield public STRK to fund it."
        : starknet.privacyCapability === "error"
          ? "Ready could not read this balance. Retry the balance check before shielding."
          : "Shield public STRK before it can be sent privately.";
  const payrollTotals = useMemo(() => {
    try {
      return recipients.reduce<Record<PayrollTokenSymbol, bigint>>((totals, recipient) => {
        totals[recipient.token] += parseTokenAmount(recipient.amount, recipient.token);
        return totals;
      }, { STRK: 0n, USDC: 0n });
    } catch {
      return null;
    }
  }, [recipients]);
  const shieldQuote = useMemo(() => {
    try {
      const token = PAYROLL_TOKENS[shieldToken];
      const grossAmount = parseTokenAmount(shieldAmount, token);
      const publicTokenBalance = starknet.publicBalances[shieldToken];
      const netAmount = starknet.privacyFee === null
        ? null
        : token.feeBehavior === "deduct-from-strk-shield"
          ? grossAmount - starknet.privacyFee
          : grossAmount;
      const shortfall = publicTokenBalance !== null && grossAmount > publicTokenBalance
        ? grossAmount - publicTokenBalance
        : 0n;
      const feeShortfall = shieldToken === "USDC" && starknet.privacyFee !== null && starknet.publicBalances.STRK !== null && starknet.privacyFee > starknet.publicBalances.STRK
        ? starknet.privacyFee - starknet.publicBalances.STRK
        : 0n;
      return {
        grossAmount,
        netAmount,
        shortfall,
        feeShortfall,
        hasSufficientBalance: publicTokenBalance !== null && shortfall === 0n && feeShortfall === 0n,
        isValid: netAmount !== null && netAmount > 0n && publicTokenBalance !== null && shortfall === 0n && feeShortfall === 0n,
      };
    } catch {
      return { grossAmount: null, netAmount: null, shortfall: 0n, feeShortfall: 0n, hasSufficientBalance: false, isValid: false };
    }
  }, [shieldAmount, shieldToken, starknet.privacyFee, starknet.publicBalances]);

  const updateRecipient = (id: number, field: keyof Omit<DraftRecipient, "id">, value: string) => {
    setRecipients((current) => current.map((recipient) => recipient.id === id ? { ...recipient, [field]: value } : recipient));
  };

  const addRecipient = () => {
    setRecipients((current) => [...current, { id: nextRecipientId, name: "", address: "", amount: shieldToken === "USDC" ? "1" : "0.001", token: shieldToken }]);
    setNextRecipientId((current) => current + 1);
  };

  const removeRecipient = (id: number) => {
    setRecipients((current) => current.filter((recipient) => recipient.id !== id));
  };

  const shieldTreasury = async () => {
    setFormError("");
    try {
      const hash = await starknet.shieldToken(shieldToken, shieldAmount);
      notify(`Shield transaction submitted · ${hash.slice(0, 10)}…`);
    } catch (shieldError) {
      setFormError(shieldError instanceof Error ? shieldError.message : "Shielding was not completed.");
    }
  };

  const submitPayroll = async () => {
    setFormError("");
    try {
      if (payrollTotals !== null) {
        for (const token of Object.keys(PAYROLL_TOKENS) as PayrollTokenSymbol[]) {
          const available = starknet.shieldedBalances[token];
          if (available !== null && payrollTotals[token] > available) {
            throw new Error(`The shielded ${token} treasury does not cover this payroll.`);
          }
        }
      }
      const hash = await starknet.runPrivatePayroll(recipients.map(({ address, amount, token }) => ({ address, amount, token })));
      notify(`Private payroll submitted · ${hash.slice(0, 10)}…`);
    } catch (payrollError) {
      setFormError(payrollError instanceof Error ? payrollError.message : "Payroll was not submitted.");
    }
  };

  return (
    <div className="product-page payroll-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--blue">PAYROLL DESK</span>
          <h2>Plan it once.<br /><em>Pay privately.</em></h2>
          <p>Prepare salaries for people and agents, review the batch, and settle through STRK20 without publishing everyone’s compensation.</p>
        </div>
        <div className="page-heading__actions">
          <button type="button" className="button button--soft" onClick={() => notify("Payroll report exported")}><Download size={17} /> Export</button>
          <button type="button" className="button button--ink" onClick={openPayroll}><Play size={17} /> Run payroll</button>
        </div>
      </section>

      <section className="private-payroll-runner reveal reveal--two" id="private-payroll">
        <div className="runner-heading">
          <div><span className="sticker sticker--yellow">LIVE · MAINNET</span><h3>Private payroll runner</h3><p>Run private STRK payroll now. Native USDC is built but stays locked until its live pool compatibility check passes.</p></div>
          <div className="runner-network"><span className={starknet.isConnected && starknet.isMainnet ? "connection-dot connection-dot--live" : "connection-dot"} /><span><small>Payroll signer</small><strong>{starknet.isConnected ? `${starknet.walletName} · ${starknet.networkName}` : "Ready not connected"}</strong></span></div>
        </div>

        <div className="runner-grid">
          <aside className="runner-setup">
            <div className={`runner-step ${starknet.isConnected ? "runner-step--done" : "runner-step--active"}`}>
              <span className="runner-step-number">1</span>
              <div><small>CONNECT SIGNER</small><strong>{starknet.isConnected ? shortStarknetAddress(starknet.address) : "Connect Ready wallet"}</strong><p>Ready holds the STRK20 privacy keys and asks for every approval.</p>{!starknet.isConnected && <Link className="button button--ink button--wide" href="/wallet">Connect Ready <WalletCards size={16} /></Link>}{starknet.isConnected && !starknet.isMainnet && <button type="button" className="button button--ink button--wide" onClick={() => starknet.switchToMainnet().catch((switchError) => setFormError(switchError instanceof Error ? switchError.message : "Network switch failed"))}>Switch to Mainnet</button>}</div>
            </div>

            <div className={`runner-step ${starknet.isConnected && starknet.isMainnet ? "runner-step--active" : ""}`}>
              <span className="runner-step-number">2</span>
              <div>
                <small>FUND PRIVATE TREASURY</small>
                <strong>{treasuryLabel}</strong>
                <p>{treasuryHelp}</p>
                {registrationRequired ? (
                  <a className="button button--soft button--wide" href={STRK20_SETUP_URL} target="_blank" rel="noreferrer">Register STRK20 account <ExternalLink size={15} /></a>
                ) : balanceUnavailable ? (
                  <Link className="button button--soft button--wide" href="/wallet">Retry on Wallet page <ArrowRight size={15} /></Link>
                ) : (
                  <>
                    <div className="token-switch" role="group" aria-label="Token to shield">
                      {(["STRK", "USDC"] as PayrollTokenSymbol[]).map((token) => (
                        <button type="button" key={token} className={shieldToken === token ? "token-switch__item token-switch__item--active" : "token-switch__item"} onClick={() => { setShieldToken(token); setShieldAmount(""); }} disabled={busy || !PAYROLL_TOKENS[token].privacyEnabled} title={!PAYROLL_TOKENS[token].privacyEnabled ? "Awaiting live STRK20 pool compatibility test" : undefined}>
                          <span>{token === "STRK" ? "S" : "$"}</span>{token}{!PAYROLL_TOKENS[token].privacyEnabled ? " · SOON" : ""}
                        </button>
                      ))}
                    </div>
                    <label className="amount-field">
                      <span>Total</span>
                      <input inputMode="decimal" value={shieldAmount} placeholder={shieldToken === "STRK" ? "e.g. 10" : "e.g. 100"} onChange={(event) => setShieldAmount(event.target.value)} aria-label={`Total ${shieldToken} to use for shielding`} />
                      <b>{shieldToken}</b>
                    </label>
                    <div className={`shield-quote ${shieldQuote.isValid ? "shield-quote--ready" : ""} ${shieldQuote.shortfall > 0n ? "shield-quote--insufficient" : ""}`}>
                      <div className="shield-quote__heading"><span>LIVE SHIELD QUOTE</span><i>{starknet.isRefreshingPrivacyFee || starknet.isRefreshingPublicBalance ? "Refreshing…" : "Mainnet live"}</i></div>
                      <div className="shield-quote__row"><span>Public {shieldToken} balance</span><strong>{formatTokenAmount(starknet.publicBalances[shieldToken], shieldToken)} {shieldToken}</strong></div>
                      <div className="shield-quote__row"><span>Total {shieldToken}</span><strong>{formatTokenAmount(shieldQuote.grossAmount, shieldToken)} {shieldToken}</strong></div>
                      <div className="shield-quote__row"><span>STRK20 privacy fee</span><strong>{starknet.privacyFee === null ? "—" : `− ${formatStrk(starknet.privacyFee)} STRK`}</strong></div>
                      <div className="shield-quote__row shield-quote__row--net"><span>Arrives shielded</span><strong>{shieldQuote.netAmount !== null && shieldQuote.netAmount > 0n ? formatTokenAmount(shieldQuote.netAmount, shieldToken) : "0"} {shieldToken}</strong></div>
                      <p>{starknet.privacyFeeError ? <>Live fee unavailable. <button type="button" onClick={() => starknet.refreshPrivacyFee().catch((feeError) => setFormError(feeError instanceof Error ? feeError.message : "Fee refresh failed"))}>Retry</button></> : starknet.publicBalanceError ? <>Wallet balance unavailable. <button type="button" onClick={() => starknet.refreshPublicBalance().catch((balanceError) => setFormError(balanceError instanceof Error ? balanceError.message : "Balance refresh failed"))}>Retry</button></> : shieldQuote.shortfall > 0n ? `Insufficient ${shieldToken} · short by ${formatTokenAmount(shieldQuote.shortfall, shieldToken)} ${shieldToken}.` : shieldQuote.feeShortfall > 0n ? `USDC shielding needs ${formatStrk(shieldQuote.feeShortfall)} more public STRK for the privacy fee.` : shieldToken === "STRK" && starknet.privacyFee !== null && shieldQuote.grossAmount !== null && shieldQuote.grossAmount <= starknet.privacyFee ? `Enter more than ${formatStrk(starknet.privacyFee)} STRK.` : shieldToken === "USDC" ? "USDC arrives intact; the privacy fee is paid separately in public STRK." : "Ready shows any separate network execution estimate before approval."}</p>
                    </div>
                    <button type="button" className="button button--soft button--wide" disabled={!starknet.isConnected || !starknet.isMainnet || !shieldQuote.isValid || starknet.privacyFee === null || starknet.publicBalances[shieldToken] === null || busy || privacyChecking || privacyUnsupported || starknet.isRefreshingPrivacyFee || starknet.isRefreshingPublicBalance} onClick={shieldTreasury}>{starknet.transaction?.kind === "shield" && busy ? <><LoaderCircle className="spin" size={16} /> {starknet.transaction.stage === "wallet" ? "Approve in Ready" : "Confirming"}</> : shieldQuote.shortfall > 0n || shieldQuote.feeShortfall > 0n ? <>Insufficient balance</> : <><ShieldCheck size={16} /> Shield {shieldQuote.isValid ? `${formatTokenAmount(shieldQuote.netAmount, shieldToken)} ${shieldToken}` : "treasury"}</>}</button>
                  </>
                )}
              </div>
            </div>

            <div className="runner-step runner-step--quiet">
              <span className="runner-step-number">3</span>
              <div><small>PRIVATE BATCH</small><strong>One wallet request</strong><p>Recipient addresses and amounts become STRK20 transfer actions inside one payroll request.</p></div>
            </div>
          </aside>

          <div className="payroll-composer">
            <div className="composer-top"><div><span className="label">RECIPIENTS</span><h4>Who gets paid?</h4></div><button type="button" className="button button--soft" onClick={addRecipient} disabled={recipients.length >= 50 || busy}><Plus size={15} /> Add recipient</button></div>
            <div className="recipient-labels"><span>Recipient</span><span>Starknet address</span><span>Private amount</span><span /></div>
            <div className="recipient-list">
              {recipients.map((recipient, index) => (
                <div className="recipient-editor" key={recipient.id}>
                  <span className="recipient-index">{index + 1}</span>
                  <label><span>Name / label</span><input value={recipient.name} placeholder={index === 0 ? "e.g. Maya Chen" : "Recipient name"} onChange={(event) => updateRecipient(recipient.id, "name", event.target.value)} /></label>
                  <label className="recipient-address"><span>Starknet address</span><input value={recipient.address} placeholder="0x…" spellCheck={false} onChange={(event) => updateRecipient(recipient.id, "address", event.target.value)} /></label>
                  <label className="recipient-amount"><span>Amount</span><input inputMode="decimal" value={recipient.amount} onChange={(event) => updateRecipient(recipient.id, "amount", event.target.value)} /><select value={recipient.token} aria-label={`Token for recipient ${index + 1}`} onChange={(event) => updateRecipient(recipient.id, "token", event.target.value as PayrollTokenSymbol)}><option value="STRK">STRK</option><option value="USDC" disabled={!PAYROLL_TOKENS.USDC.privacyEnabled}>USDC{PAYROLL_TOKENS.USDC.privacyEnabled ? "" : " · live test pending"}</option></select></label>
                  <button type="button" className="recipient-remove" aria-label={`Remove recipient ${index + 1}`} disabled={recipients.length === 1 || busy} onClick={() => removeRecipient(recipient.id)}><X size={15} /></button>
                </div>
              ))}
            </div>

            <div className="recipient-note"><ShieldCheck size={17} /><span><strong>Before payday</strong><small>Each destination must be a valid Starknet account accepted by STRK20. Ready will reject an ineligible recipient before signing.</small></span></div>

            <div className="composer-summary">
              <div><small>Recipients</small><strong>{recipients.length}</strong></div><div><small>Private total</small><strong>{payrollTotals ? `${formatTokenAmount(payrollTotals.STRK, "STRK")} STRK · ${formatTokenAmount(payrollTotals.USDC, "USDC")} USDC` : "—"}</strong></div><div><small>Shielded treasury</small><strong>{formatTokenAmount(starknet.shieldedBalances.STRK, "STRK")} STRK · {formatTokenAmount(starknet.shieldedBalances.USDC, "USDC")} USDC</strong></div>
              <button type="button" className="button button--ink" disabled={!starknet.isConnected || !starknet.isMainnet || !canRunPayroll || busy || payrollTotals === null} onClick={submitPayroll}>{starknet.transaction?.kind === "payroll" && busy ? <><LoaderCircle className="spin" size={17} /> {starknet.transaction.stage === "wallet" ? "Approve in Ready" : "Confirming on Mainnet"}</> : <>Approve private payroll <ArrowRight size={17} /></>}</button>
            </div>

            {formError && <div className="runner-error"><X size={16} /><span>{formError}</span></div>}
            {starknet.transaction && (
              <div className={`transaction-receipt transaction-receipt--${starknet.transaction.stage}`}>
                <span className="transaction-receipt-icon">{starknet.transaction.stage === "confirmed" ? <CheckCircle2 size={20} /> : starknet.transaction.stage === "failed" ? <X size={19} /> : <LoaderCircle className="spin" size={19} />}</span>
                <span><small>{starknet.transaction.stage === "wallet" ? "READY IS PREPARING THE PROOF" : starknet.transaction.stage === "confirming" ? "SUBMITTED TO MAINNET" : starknet.transaction.stage === "confirmed" ? "TRANSACTION CONFIRMED" : "TRANSACTION NEEDS ATTENTION"}</small><strong>{starknet.transaction.label}</strong>{starknet.transaction.kind === "shield" && starknet.transaction.grossAmount !== undefined && starknet.transaction.privacyFee !== undefined && <p>{starknet.transaction.token === "USDC" ? `${formatTokenAmount(starknet.transaction.grossAmount, "USDC")} USDC shields while ${formatStrk(starknet.transaction.privacyFee)} public STRK covers the privacy fee.` : `${formatStrk(starknet.transaction.grossAmount)} STRK total − ${formatStrk(starknet.transaction.privacyFee)} STRK privacy fee = ${formatStrk(starknet.transaction.netAmount ?? null)} STRK shielded.`}</p>}{starknet.transaction.stage === "wallet" && <p>Payo sent one request. Reject any repeated Ready prompt for this same transaction.</p>}{starknet.transaction.error && <p>{starknet.transaction.error}</p>}</span>
                {starknet.transaction.hash && <a href={`${STARKNET_MAINNET_EXPLORER}/tx/${starknet.transaction.hash}`} target="_blank" rel="noreferrer">View receipt <ExternalLink size={13} /></a>}
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="payroll-stage-card reveal reveal--three">
        <div className="payroll-stage__copy">
          <div className="stage-status"><span /> READY TO REVIEW</div>
          <h3>August payroll</h3>
          <p>All 16 recipients are registered and the private treasury is funded. One review stands between your team and payday.</p>
          <div className="stage-people" aria-label="12 humans and 4 agents">
            {["MC", "TB", "AJ", "SO", "AI", "AI"].map((initials, index) => (
              <span className={initials === "AI" ? "stage-person stage-person--agent" : "stage-person"} key={`${initials}-${index}`}>{initials}</span>
            ))}
            <b>+10</b>
          </div>
          <button type="button" className="button button--ink" onClick={openPayroll}>Review 16 payments <ArrowRight size={17} /></button>
        </div>

        <div className="payday-calendar" aria-hidden="true">
          <span className="calendar-spark calendar-spark--one">✦</span>
          <span className="calendar-spark calendar-spark--two">✦</span>
          <div className="calendar-rings"><i /><i /><i /></div>
          <div className="calendar-top">AUGUST</div>
          <strong>27</strong>
          <span>THURSDAY · PAYDAY</span>
          <div className="calendar-face"><i /><i /><b /></div>
          <div className="calendar-feet"><i /><i /></div>
        </div>

        <div className="payroll-stage__summary">
          <div><span>Total payroll</span><strong>$12,640.00</strong><small>Illustrative monthly plan</small></div>
          <div className="stage-summary-row"><span><Users size={15} /> Recipients</span><b>16</b></div>
          <div className="stage-summary-row"><span><CircleDollarSign size={15} /> Average payment</span><b>$790</b></div>
          <div className="stage-summary-row"><span><CalendarDays size={15} /> Scheduled</span><b>Aug 27</b></div>
          <div className="funds-check"><CheckCircle2 size={17} /><span><strong>Treasury is ready</strong><small>$35,600.80 remains after payroll</small></span></div>
        </div>
      </section>

      <section className="payroll-stats reveal reveal--four">
        <article className="mini-stat mini-stat--yellow">
          <span className="mini-stat__icon"><CircleDollarSign size={18} /></span>
          <div><small>Paid this year</small><strong>$84,390</strong><em>7 private runs</em></div>
        </article>
        <article className="mini-stat mini-stat--blue">
          <span className="mini-stat__icon"><Users size={18} /></span>
          <div><small>Active recipients</small><strong>16</strong><em>12 people · 4 agents</em></div>
        </article>
        <article className="mini-stat mini-stat--green">
          <span className="mini-stat__icon"><ShieldCheck size={18} /></span>
          <div><small>Payment success</small><strong>100%</strong><em>Nothing needs attention</em></div>
        </article>
      </section>

      <section className="runs-section reveal reveal--five">
        <div className="section-heading">
          <div><span className="label">THE PAPER TRAIL</span><h3>Payroll runs</h3></div>
          <div className="filter-tabs" role="tablist" aria-label="Filter payroll runs">
            {filters.map((item) => (
              <button type="button" role="tab" aria-selected={filter === item} className={filter === item ? "filter-tab filter-tab--active" : "filter-tab"} key={item} onClick={() => setFilter(item)}>{item}</button>
            ))}
          </div>
        </div>

        <div className="runs-card">
          <div className="table-head"><span>Payroll</span><span>Recipients</span><span>Status</span><span>Total</span><span /></div>
          {visibleRuns.map((run) => (
            <button type="button" className="run-row" key={run.month} onClick={() => notify(`${run.month} opened`)}>
              <span className={`run-mark run-mark--${run.tone}`}>{run.month.slice(0, 3).toUpperCase()}</span>
              <span className="run-name"><strong>{run.month}</strong><small>{run.detail}</small></span>
              <span className="run-recipients">{run.recipients}</span>
              <span className={`run-status run-status--${run.status.toLowerCase()}`}><i />{run.status}</span>
              <strong className="run-amount">{run.amount}</strong>
              <MoreHorizontal className="run-more" size={18} />
            </button>
          ))}
          {visibleRuns.length === 0 && <div className="empty-row"><Sparkles size={21} /><strong>No payrolls here yet.</strong><span>Try a different status.</span></div>}
        </div>
      </section>

      <section className="rhythm-card reveal reveal--five">
        <div className="rhythm-icon"><Clock3 size={24} /><span>↻</span></div>
        <div><span className="label">MONTHLY RHYTHM</span><h3>Your next three paydays are planned.</h3><p>August 27 · September 28 · October 28</p></div>
        <button type="button" className="button button--soft" onClick={() => notify("Payroll schedule opened")}><PencilLine size={16} /> Edit schedule</button>
      </section>
    </div>
  );
}
