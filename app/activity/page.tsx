"use client";

import {
  ArrowDownLeft,
  ArrowUpRight,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  Eye,
  EyeOff,
  FileText,
  Filter,
  LockKeyhole,
  ReceiptText,
  Search,
  ShieldCheck,
  Sparkles,
  WalletCards,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useAppShell } from "../ui/app-shell";

type ActivityKind = "Payroll" | "Treasury" | "Agent";

const events: Array<{
  day: string;
  title: string;
  detail: string;
  time: string;
  amount: string;
  kind: ActivityKind;
  icon: typeof Check;
  tone: string;
  hash?: string;
}> = [
  { day: "Today", title: "July payroll completed", detail: "16 private transfers settled", time: "10:42 AM", amount: "− $12,640", kind: "Payroll", icon: CheckCircle2, tone: "green", hash: "0x07c0…29fe" },
  { day: "Today", title: "Payment receipt disclosed", detail: "Maya shared proof with Acorn Labs", time: "9:18 AM", amount: "$3,200", kind: "Payroll", icon: Eye, tone: "coral" },
  { day: "August 18", title: "Treasury shielded", detail: "Public USDC moved into private balance", time: "4:04 PM", amount: "+ $20,000", kind: "Treasury", icon: ArrowDownLeft, tone: "blue", hash: "0x04b2…11aa" },
  { day: "August 18", title: "Agent allowance updated", detail: "Scout · Research budget", time: "11:32 AM", amount: "$420 cap", kind: "Agent", icon: Bot, tone: "yellow" },
  { day: "August 17", title: "Private transfer", detail: "Recipient and amount encrypted", time: "3:50 PM", amount: "Private", kind: "Payroll", icon: EyeOff, tone: "green", hash: "0x0919…70bd" },
  { day: "August 17", title: "Treasury withdrawal", detail: "Unshielded to operating wallet", time: "12:10 PM", amount: "− $850", kind: "Treasury", icon: ArrowUpRight, tone: "coral", hash: "0x0612…9ea1" },
  { day: "August 16", title: "Patch connected through MCP", detail: "Scopes: read budget, request payment", time: "5:22 PM", amount: "Connected", kind: "Agent", icon: Bot, tone: "blue" },
];

const activityFilters = ["All", "Payroll", "Treasury", "Agent"] as const;

export default function ActivityPage() {
  const { notify } = useAppShell();
  const [filter, setFilter] = useState<(typeof activityFilters)[number]>("All");
  const [query, setQuery] = useState("");
  const [copiedHash, setCopiedHash] = useState("");

  const visibleEvents = useMemo(() => {
    return events.filter((event) => {
      const matchesFilter = filter === "All" || event.kind === filter;
      const matchesQuery = `${event.title} ${event.detail}`.toLowerCase().includes(query.toLowerCase());
      return matchesFilter && matchesQuery;
    });
  }, [filter, query]);

  const groupedEvents = visibleEvents.reduce<Record<string, typeof events>>((groups, event) => {
    (groups[event.day] ??= []).push(event);
    return groups;
  }, {});

  const copyHash = async (hash: string) => {
    await navigator.clipboard?.writeText(hash);
    setCopiedHash(hash);
    notify("Transaction hash copied");
    window.setTimeout(() => setCopiedHash(""), 1600);
  };

  return (
    <div className="product-page activity-page-full">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--coral">PRIVATE RECORDS</span>
          <h2>Clear records.<br /><em>Quiet details.</em></h2>
          <p>Track what happened, verify settlement, and create selective receipts without exposing the private payroll behind them.</p>
        </div>
        <div className="page-heading__actions">
          <button type="button" className="button button--soft" onClick={() => notify("CSV export prepared")}><Download size={17} /> Export</button>
          <button type="button" className="button button--ink" onClick={() => notify("Disclosure receipt flow opened")}><ReceiptText size={17} /> New receipt</button>
        </div>
      </section>

      <section className="visibility-card reveal reveal--two">
        <div className="visibility-art" aria-hidden="true">
          <div className="visibility-folder"><span>PRIVATE</span><EyeOff size={26} /><i /><i /></div>
          <span className="visibility-key">✦</span>
          <div className="visibility-lock"><LockKeyhole size={22} /></div>
        </div>
        <div className="visibility-copy">
          <span className="label">YOUR PRIVACY AT A GLANCE</span>
          <h3>The record proves payment—not everyone’s salary.</h3>
          <p>Payo separates operational evidence from sensitive details, so teams can stay accountable without making compensation public.</p>
        </div>
        <div className="visibility-legend">
          <div><span className="visibility-icon visibility-icon--hidden"><EyeOff size={16} /></span><span><small>Hidden</small><strong>Recipient · salary · token</strong></span></div>
          <div><span className="visibility-icon visibility-icon--visible"><Eye size={16} /></span><span><small>Visible onchain</small><strong>Pool interaction · timing</strong></span></div>
        </div>
      </section>

      <section className="activity-kpis reveal reveal--three">
        <article><span className="activity-kpi-icon activity-kpi-icon--green"><CheckCircle2 size={18} /></span><div><small>Settled this month</small><strong>18</strong><em>100% successful</em></div></article>
        <article><span className="activity-kpi-icon activity-kpi-icon--blue"><ShieldCheck size={18} /></span><div><small>Private volume</small><strong>$32,640</strong><em>Payroll + treasury</em></div></article>
        <article><span className="activity-kpi-icon activity-kpi-icon--yellow"><FileText size={18} /></span><div><small>Receipts shared</small><strong>3</strong><em>Explicitly disclosed</em></div></article>
        <article><span className="activity-kpi-icon activity-kpi-icon--coral"><Bot size={18} /></span><div><small>Agent requests</small><strong>7</strong><em>All within policy</em></div></article>
      </section>

      <div className="activity-layout reveal reveal--four">
        <section className="activity-feed-card">
          <div className="feed-header">
            <div><span className="label">AUDIT TRAIL</span><h3>All activity</h3></div>
            <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search records" aria-label="Search activity" /></label>
          </div>
          <div className="filter-tabs feed-tabs" role="tablist" aria-label="Filter activity">
            {activityFilters.map((item) => (
              <button type="button" role="tab" aria-selected={filter === item} className={filter === item ? "filter-tab filter-tab--active" : "filter-tab"} key={item} onClick={() => setFilter(item)}>{item}</button>
            ))}
            <button type="button" className="feed-filter-more" aria-label="More filters" onClick={() => notify("Date filters opened")}><Filter size={14} /> More</button>
          </div>

          <div className="timeline">
            {Object.entries(groupedEvents).map(([day, dayEvents]) => (
              <div className="timeline-day" key={day}>
                <div className="timeline-day__label"><span>{day}</span><i /></div>
                {dayEvents.map((event) => {
                  const Icon = event.icon;
                  return (
                    <article className="timeline-event" key={`${event.title}-${event.time}`}>
                      <span className={`timeline-icon timeline-icon--${event.tone}`}><Icon size={17} /></span>
                      <div className="timeline-event__main"><strong>{event.title}</strong><span>{event.detail}</span><small>{event.time}</small></div>
                      <div className="timeline-event__value"><strong>{event.amount}</strong><span className={`event-kind event-kind--${event.kind.toLowerCase()}`}>{event.kind}</span></div>
                      {event.hash ? (
                        <button type="button" className="hash-button" onClick={() => copyHash(event.hash!)}>
                          {copiedHash === event.hash ? <Check size={13} /> : <Copy size={13} />} {event.hash}
                        </button>
                      ) : <span className="hash-button hash-button--muted"><LockKeyhole size={12} /> Offchain record</span>}
                    </article>
                  );
                })}
              </div>
            ))}
            {visibleEvents.length === 0 && <div className="directory-empty"><Search size={24} /><strong>No records found</strong><span>Try a different search or filter.</span></div>}
          </div>
        </section>

        <aside className="activity-side">
          <section className="privacy-score-card">
            <div className="privacy-score-top"><span className="label">PRIVACY COVERAGE</span><Sparkles size={17} /></div>
            <div className="privacy-score-body">
              <div className="score-ring"><span><strong>94</strong><small>/ 100</small></span></div>
              <div><h3>Looking good.</h3><p>Most team funds stay shielded between paydays.</p></div>
            </div>
            <div className="score-checks">
              <span><Check size={13} /> Private payroll enabled</span>
              <span><Check size={13} /> Agent scopes limited</span>
              <span><Check size={13} /> No failed transfers</span>
            </div>
            <button type="button" className="button button--soft button--wide" onClick={() => notify("Privacy report opened")}><ShieldCheck size={16} /> View privacy report</button>
          </section>

          <section className="receipts-card">
            <div className="receipt-doodle" aria-hidden="true"><FileText size={28} /><span>✓</span></div>
            <span className="label">SELECTIVE DISCLOSURE</span>
            <h3>Share one fact.<br />Keep the rest private.</h3>
            <p>Create proof of a payment for accounting, a contractor, or an auditor without revealing the whole payroll.</p>
            <button type="button" className="button button--ink button--wide" onClick={() => notify("Receipt builder opened")}>Create a receipt <ExternalLink size={15} /></button>
          </section>

          <section className="pool-status-card">
            <span className="pool-pulse"><i /></span>
            <div><small>STRK20 pool</small><strong>Healthy · Mainnet</strong></div>
            <WalletCards size={18} />
          </section>
        </aside>
      </div>
    </div>
  );
}
