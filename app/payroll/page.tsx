"use client";

import {
  ArrowRight,
  CalendarDays,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Download,
  MoreHorizontal,
  PencilLine,
  Play,
  ShieldCheck,
  Sparkles,
  Users,
} from "lucide-react";
import { useState } from "react";
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

export default function PayrollPage() {
  const { openPayroll, notify } = useAppShell();
  const [filter, setFilter] = useState<(typeof filters)[number]>("All");

  const visibleRuns = filter === "All" ? runs : runs.filter((run) => run.status === filter);

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

      <section className="payroll-stage-card reveal reveal--two">
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
          <div><span>Total payroll</span><strong>$12,640.00</strong><small>USDC · Shielded balance</small></div>
          <div className="stage-summary-row"><span><Users size={15} /> Recipients</span><b>16</b></div>
          <div className="stage-summary-row"><span><CircleDollarSign size={15} /> Average payment</span><b>$790</b></div>
          <div className="stage-summary-row"><span><CalendarDays size={15} /> Scheduled</span><b>Aug 27</b></div>
          <div className="funds-check"><CheckCircle2 size={17} /><span><strong>Treasury is ready</strong><small>$35,600.80 remains after payroll</small></span></div>
        </div>
      </section>

      <section className="payroll-stats reveal reveal--three">
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

      <section className="runs-section reveal reveal--four">
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
