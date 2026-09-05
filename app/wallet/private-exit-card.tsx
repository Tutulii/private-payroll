"use client";

import {
  AlertTriangle,
  ArrowLeftRight,
  Check,
  ExternalLink,
  LoaderCircle,
  LockKeyhole,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { PrivateExitQuote } from "@/lib/domain/private-exit";
import { assertPayoPrivateExitQuote } from "@/lib/starknet/private-exit";
import {
  formatTokenAmount,
  parseTokenAmount,
  STARKNET_MAINNET_EXPLORER,
  type PayrollTokenSymbol,
  useStarknetWallet,
} from "../starknet/starknet-wallet";
import { useAppShell } from "../ui/app-shell";
import "./private-exit-card.css";

type ExitMode = "private_swap" | "public_withdrawal" | "unsupported";

type PrivateExitReadiness = {
  enabled: boolean;
  code: "READY" | "ANONYMIZER_NOT_CONFIGURED" | "ANONYMIZER_NOT_VERIFIED";
  message: string;
  routeId?: string;
  executorAddress?: string | null;
  verifiedBlockNumber?: number | null;
};

function oppositeToken(token: PayrollTokenSymbol): PayrollTokenSymbol {
  return token === "STRK" ? "USDC" : "STRK";
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text.trim()) throw new Error(`PAYO returned an empty response (HTTP ${response.status}).`);
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error(`PAYO returned an unreadable response (HTTP ${response.status}).`);
  }
}

export function PrivateExitCard() {
  const starknet = useStarknetWallet();
  const { notify } = useAppShell();
  const [mode, setMode] = useState<ExitMode>("private_swap");
  const [fromToken, setFromToken] = useState<PayrollTokenSymbol>("STRK");
  const toToken = oppositeToken(fromToken);
  const [amount, setAmount] = useState("");
  const [slippageBps, setSlippageBps] = useState(100);
  const [readiness, setReadiness] = useState<PrivateExitReadiness | null>(null);
  const [readinessLoading, setReadinessLoading] = useState(true);
  const [quote, setQuote] = useState<PrivateExitQuote | null>(null);
  const [quoteLoading, setQuoteLoading] = useState(false);
  const [quoteError, setQuoteError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [withdrawRecipient, setWithdrawRecipient] = useState("");
  const [publicAcknowledged, setPublicAcknowledged] = useState(false);
  const [clock, setClock] = useState(() => Date.now());

  const loadReadiness = useCallback(async () => {
    try {
      const response = await fetch("/api/v1/private-exit/readiness", { cache: "no-store" });
      const payload = await readJson(response);
      const next = payload.readiness as PrivateExitReadiness | undefined;
      if (!next || typeof next.enabled !== "boolean" || typeof next.message !== "string") {
        throw new Error("PAYO returned an invalid private-exit readiness response.");
      }
      setReadiness(next);
    } catch (error) {
      setReadiness({
        enabled: false,
        code: "ANONYMIZER_NOT_VERIFIED",
        message: error instanceof Error ? error.message : "Private-exit readiness is unavailable.",
      });
    } finally {
      setReadinessLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void loadReadiness(); }, 0);
    return () => window.clearTimeout(timer);
  }, [loadReadiness]);

  useEffect(() => {
    if (!quote) return;
    const timer = window.setInterval(() => setClock(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [quote]);

  const fetchPrivateQuote = useCallback(async (
    signal?: AbortSignal,
  ): Promise<PrivateExitQuote> => {
    const amountAtomic = parseTokenAmount(amount, fromToken);
    const parameters = new URLSearchParams({
      from: fromToken,
      to: toToken,
      amountAtomic: amountAtomic.toString(),
      slippageBps: String(slippageBps),
    });
    const response = await fetch(`/api/v1/private-exit/quote?${parameters}`, {
      cache: "no-store",
      signal,
    });
    const payload = await readJson(response);
    if (!response.ok) {
      const apiError = payload.error as { message?: unknown } | undefined;
      throw new Error(typeof apiError?.message === "string"
        ? apiError.message
        : "The private swap quote is unavailable.");
    }
    const next = assertPayoPrivateExitQuote(payload.quote);
    if (
      next.fromToken !== fromToken
      || next.toToken !== toToken
      || BigInt(next.amountInAtomic) !== amountAtomic
      || next.slippageBps !== slippageBps
    ) throw new Error("PAYO returned a quote for different swap terms.");
    return next;
  }, [amount, fromToken, slippageBps, toToken]);

  const amountInputError = useMemo(() => {
    if (!amount.trim()) return "";
    try { parseTokenAmount(amount, fromToken); return ""; }
    catch (error) { return error instanceof Error ? error.message : "Enter a valid private amount."; }
  }, [amount, fromToken]);

  const clearQuote = () => {
    setQuote(null);
    setQuoteError("");
    setQuoteLoading(false);
  };

  useEffect(() => {
    if (mode !== "private_swap" || !readiness?.enabled || !amount.trim() || amountInputError) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setQuoteLoading(true);
      void fetchPrivateQuote(controller.signal).then(
        (next) => {
          setQuote(next);
          setClock(Date.now());
          setQuoteLoading(false);
        },
        (error) => {
          if (controller.signal.aborted) return;
          setQuoteError(error instanceof Error ? error.message : "The private swap quote failed.");
          setQuoteLoading(false);
        },
      );
    }, 550);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [amount, amountInputError, fetchPrivateQuote, mode, readiness?.enabled]);

  const quoteExpired = Boolean(quote && clock > quote.expiresAt);
  const privateBalance = starknet.shieldedBalances[fromToken];
  const enteredAtomic = useMemo(() => {
    try { return amount.trim() ? parseTokenAmount(amount, fromToken) : 0n; } catch { return 0n; }
  }, [amount, fromToken]);
  const visiblyInsufficient = privateBalance !== null && enteredAtomic > privateBalance;
  const privateTransaction = starknet.transaction?.kind === "private_swap"
    ? starknet.transaction
    : null;
  const publicTransaction = starknet.transaction?.kind === "public_withdrawal"
    ? starknet.transaction
    : null;

  const submitPrivateSwap = async () => {
    setActionError("");
    setActionBusy(true);
    try {
      const freshQuote = await fetchPrivateQuote();
      setQuote(freshQuote);
      await starknet.runPrivateSwap(freshQuote);
      notify("Private swap submitted to Ready");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The private swap could not start.");
    } finally {
      setActionBusy(false);
    }
  };

  const submitPublicWithdrawal = async () => {
    setActionError("");
    setActionBusy(true);
    try {
      await starknet.runPublicWithdrawal({
        token: fromToken,
        amount,
        recipient: withdrawRecipient,
        acknowledgedPublicDisclosure: publicAcknowledged,
      });
      notify("Public withdrawal submitted to Ready");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The public withdrawal could not start.");
    } finally {
      setActionBusy(false);
    }
  };

  const walletReady = starknet.isConnected
    && starknet.isMainnet
    && (starknet.privacyCapability === "zero" || starknet.privacyCapability === "available");

  return (
    <section className="private-exit-card reveal reveal--five" aria-labelledby="private-exit-title">
      <div className="private-exit-heading">
        <div className="private-exit-heading__icon"><ArrowLeftRight size={22} /></div>
        <div>
          <span className="label">PRIVATE EXIT BOUNDARY</span>
          <h3 id="private-exit-title">Know where privacy ends.</h3>
          <p>Swap STRK and USDC back into an encrypted note, or explicitly acknowledge a public exit.</p>
        </div>
        <span className="private-exit-standard"><ShieldCheck size={14} /> STRK20 · Ekubo</span>
      </div>

      <div className="private-exit-tabs" role="tablist" aria-label="Exit route">
        <button type="button" role="tab" aria-selected={mode === "private_swap"} onClick={() => { clearQuote(); setMode("private_swap"); setActionError(""); }}><LockKeyhole size={15} /> Private swap</button>
        <button type="button" role="tab" aria-selected={mode === "public_withdrawal"} onClick={() => { clearQuote(); setMode("public_withdrawal"); setActionError(""); }}><ShieldAlert size={15} /> Public withdrawal</button>
        <button type="button" role="tab" aria-selected={mode === "unsupported"} onClick={() => { clearQuote(); setMode("unsupported"); setActionError(""); }}><AlertTriangle size={15} /> Bridge / exchange</button>
      </div>

      {mode === "private_swap" && (
        <div className="private-exit-workspace">
          <div className="private-exit-form">
            <label><span>You send</span><div className="private-exit-amount"><input value={amount} onChange={(event) => { clearQuote(); setAmount(event.target.value); }} inputMode="decimal" placeholder="0.00" aria-label="Private swap amount" /><select value={fromToken} onChange={(event) => { clearQuote(); setFromToken(event.target.value as PayrollTokenSymbol); }} aria-label="Private swap input token"><option value="STRK">STRK</option><option value="USDC">USDC</option></select></div><small>Private balance · {formatTokenAmount(privateBalance, fromToken)} {fromToken}</small></label>
            <div className="private-exit-arrow"><ArrowLeftRight size={15} /></div>
            <label><span>You receive privately</span><div className="private-exit-output"><strong>{quote && !quoteExpired ? formatTokenAmount(BigInt(quote.expectedOutAtomic), toToken) : "—"}</strong><em>{toToken}</em></div><small>{quote ? `Minimum ${formatTokenAmount(BigInt(quote.minimumOutAtomic), toToken)} ${toToken}` : "One encrypted output note"}</small></label>
            <label className="private-exit-slippage"><span>Maximum slippage</span><select value={slippageBps} onChange={(event) => { clearQuote(); setSlippageBps(Number(event.target.value)); }}><option value={50}>0.50%</option><option value={100}>1.00%</option><option value={200}>2.00%</option></select></label>
          </div>

          <div className="private-exit-proofline">
            {readinessLoading ? <><LoaderCircle className="spin" size={14} /> Verifying the on-chain executor…</> : readiness?.enabled ? <><Check size={14} /> Official anonymizer class verified{readiness.verifiedBlockNumber ? ` at block ${readiness.verifiedBlockNumber.toLocaleString()}` : ""}</> : <><LockKeyhole size={14} /> {readiness?.message ?? "Private route is not configured."} <button type="button" onClick={() => { setReadinessLoading(true); void loadReadiness(); }}>Retry</button></>}
          </div>
          <div className="private-exit-privacy-note"><ShieldCheck size={17} /><span><strong>Your treasury identity and output note stay shielded.</strong><small>The anonymous swap amount and Ekubo pool route remain visible to the external protocol. PAYO does not call that information confidential.</small></span></div>
          {quoteLoading && <p className="private-exit-message"><LoaderCircle className="spin" size={14} /> Reading a canonical single-hop quote…</p>}
          {(amountInputError || quoteError) && <p className="private-exit-error">{amountInputError || quoteError}</p>}
          {visiblyInsufficient && <p className="private-exit-error">Insufficient private {fromToken} balance before the additional STRK20 fee reserve.</p>}
          {quoteExpired && <p className="private-exit-error">This quote expired. PAYO will request a fresh quote before opening Ready.</p>}
          <button type="button" className="button button--ink private-exit-submit" disabled={!walletReady || !readiness?.enabled || !quote || quoteExpired || visiblyInsufficient || actionBusy || quoteLoading || Boolean(starknet.transaction && ["wallet", "confirming"].includes(starknet.transaction.stage))} onClick={() => void submitPrivateSwap()}>{actionBusy || privateTransaction?.stage === "wallet" || privateTransaction?.stage === "confirming" ? <><LoaderCircle className="spin" size={16} /> {privateTransaction?.stage === "wallet" ? "Approve in Ready" : "Preparing private swap"}</> : <>Swap into private {toToken} <ArrowLeftRight size={16} /></>}</button>
          {!walletReady && <small className="private-exit-footnote">Connect a registered Ready account on Mainnet to use private exits.</small>}
          {privateTransaction?.stage === "confirmed" && privateTransaction.hash && <a className="private-exit-receipt" href={`${STARKNET_MAINNET_EXPLORER}/tx/${privateTransaction.hash}`} target="_blank" rel="noreferrer"><Check size={14} /> Private swap confirmed <ExternalLink size={12} /></a>}
        </div>
      )}

      {mode === "public_withdrawal" && (
        <div className="private-exit-workspace private-exit-workspace--public">
          <div className="private-exit-warning"><ShieldAlert size={20} /><span><strong>This permanently leaves PAYO’s privacy boundary.</strong><small>The destination address, token and amount become public on Starknet. Anyone may link and index them.</small></span></div>
          <div className="private-exit-public-grid">
            <label><span>Amount</span><div className="private-exit-amount"><input value={amount} onChange={(event) => { clearQuote(); setAmount(event.target.value); }} inputMode="decimal" placeholder="0.00" aria-label="Public withdrawal amount" /><select value={fromToken} onChange={(event) => { clearQuote(); setFromToken(event.target.value as PayrollTokenSymbol); }} aria-label="Public withdrawal token"><option value="STRK">STRK</option><option value="USDC">USDC</option></select></div></label>
            <label><span>Public Starknet recipient</span><input className="private-exit-address" value={withdrawRecipient} onChange={(event) => setWithdrawRecipient(event.target.value)} placeholder="0x…" spellCheck={false} /></label>
          </div>
          <label className="private-exit-ack"><input type="checkbox" checked={publicAcknowledged} onChange={(event) => setPublicAcknowledged(event.target.checked)} /><span>I understand this exact withdrawal becomes publicly linkable and PAYO cannot restore its privacy.</span></label>
          <button type="button" className="button private-exit-public-button" disabled={!walletReady || !publicAcknowledged || !amount.trim() || Boolean(amountInputError) || visiblyInsufficient || !withdrawRecipient.trim() || actionBusy || Boolean(starknet.transaction && ["wallet", "confirming"].includes(starknet.transaction.stage))} onClick={() => void submitPublicWithdrawal()}>{actionBusy || publicTransaction?.stage === "wallet" || publicTransaction?.stage === "confirming" ? <><LoaderCircle className="spin" size={16} /> {publicTransaction?.stage === "wallet" ? "Approve public exit in Ready" : "Confirming public exit"}</> : <><ShieldAlert size={16} /> Withdraw publicly</>}</button>
          {publicTransaction?.stage === "confirmed" && publicTransaction.hash && <a className="private-exit-receipt" href={`${STARKNET_MAINNET_EXPLORER}/tx/${publicTransaction.hash}`} target="_blank" rel="noreferrer"><Check size={14} /> Public withdrawal confirmed <ExternalLink size={12} /></a>}
        </div>
      )}

      {mode === "unsupported" && (
        <div className="private-exit-workspace private-exit-workspace--blocked">
          <span className="private-exit-blocked-icon"><AlertTriangle size={24} /></span>
          <div><strong>Unsupported destinations are blocked.</strong><p>PAYO will not wrap a bridge, centralized exchange or arbitrary contract call in a “private” label. Use the reviewed single-hop route above, or choose the explicit public withdrawal and accept its disclosure.</p></div>
        </div>
      )}

      {actionError && <p className="private-exit-error" role="alert">{actionError}</p>}
    </section>
  );
}
