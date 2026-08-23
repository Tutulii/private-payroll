"use client";

import {
  ArrowRight,
  Bot,
  CalendarDays,
  Check,
  Copy,
  MoreHorizontal,
  Plus,
  ShieldCheck,
  WalletCards,
  Zap,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { useAppShell } from "./ui/app-shell";

const team = [
  { name: "Maya Chen", role: "Product designer", amount: "$3,200", tone: "coral", type: "human", initials: "MC" },
  { name: "Theo Brooks", role: "Cairo engineer", amount: "$4,100", tone: "blue", type: "human", initials: "TB" },
  { name: "Scout", role: "Research agent", amount: "$420", tone: "yellow", type: "agent", initials: "SC" },
  { name: "Patch", role: "QA agent", amount: "$280", tone: "green", type: "agent", initials: "PA" },
];

const activity = [
  { title: "July payroll completed", meta: "16 private transfers · 2m ago", amount: "− $12,640", icon: Check, tone: "green" },
  { title: "Treasury shielded", meta: "USDC · Aug 18", amount: "+ $20,000", icon: ShieldCheck, tone: "blue" },
  { title: "Scout joined the team", meta: "MCP agent · Aug 17", amount: "Ready", icon: Bot, tone: "yellow" },
];

function PayrollIllustration() {
  return (
    <div className="payroll-art" aria-hidden="true">
      <span className="art-spark art-spark--one">✦</span>
      <span className="art-spark art-spark--two">✦</span>
      <span className="art-coin art-coin--one">$</span>
      <span className="art-coin art-coin--two">$</span>
      <div className="art-cloud art-cloud--one" />
      <div className="art-cloud art-cloud--two" />
      <div className="art-card art-card--back">
        <span className="art-card__line" />
        <span className="art-card__line art-card__line--short" />
      </div>
      <div className="art-card art-card--front">
        <div className="art-card__face">
          <span className="face-eye" />
          <span className="face-eye" />
          <span className="face-smile" />
        </div>
        <div className="art-card__amount">PAY DAY!</div>
        <div className="art-card__legs"><span /><span /></div>
      </div>
      <div className="art-shield"><ShieldCheck size={30} strokeWidth={2.5} /></div>
      <div className="art-ground" />
    </div>
  );
}

export default function OverviewPage() {
  const { openPayroll, notify } = useAppShell();
  const [copied, setCopied] = useState(false);

  const copyMcp = async () => {
    await navigator.clipboard?.writeText("npx payo-mcp connect --team acorn-labs");
    setCopied(true);
    notify("MCP command copied");
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="content-grid">
      <section className="hero-card reveal reveal--one">
        <div className="hero-copy">
          <span className="sticker">NEXT PAYDAY</span>
          <h2>Everyone gets paid<br />in <span>4 days.</span></h2>
          <p>Your August payroll is ready for 12 people and 4 agents. Salaries stay between you and your team.</p>
          <div className="hero-actions">
            <button type="button" className="button button--ink" onClick={openPayroll}>
              Review payroll <ArrowRight size={18} />
            </button>
            <button type="button" className="text-button" onClick={() => notify("Payday is August 27")}>
              Aug 27 <CalendarDays size={16} />
            </button>
          </div>
        </div>
        <PayrollIllustration />
      </section>

      <section className="balance-card reveal reveal--two">
        <div className="card-heading">
          <div><span className="label">PRIVATE TREASURY</span><h3>$48,240<span>.80</span></h3></div>
          <span className="shield-badge"><ShieldCheck size={17} /> Shielded</span>
        </div>
        <div className="balance-meter"><span /></div>
        <div className="balance-meta">
          <div><span>August payroll</span><strong>$12,640</strong></div>
          <div><span>After payroll</span><strong>$35,600.80</strong></div>
        </div>
        <button type="button" className="button button--cream button--wide" onClick={() => notify("Treasury funding flow opened")}>
          <WalletCards size={18} /> Add private funds
        </button>
      </section>

      <section className="panel team-panel reveal reveal--three">
        <div className="panel-title">
          <div><span className="label">YOUR CREW</span><h3>People & agents</h3></div>
          <button type="button" className="circle-add" aria-label="Add team member" onClick={() => notify("Invite flow opened")}><Plus size={19} /></button>
        </div>
        <div className="team-list">
          {team.map((member) => (
            <button type="button" className="team-row" key={member.name} onClick={() => notify(`${member.name} selected`)}>
              <div className={`avatar avatar--${member.tone}`}>
                {member.type === "agent" ? <Bot size={18} /> : member.initials}
                <span className="online-dot" />
              </div>
              <div className="team-info"><strong>{member.name}</strong><span>{member.role}</span></div>
              <span className={`type-pill ${member.type === "agent" ? "type-pill--agent" : ""}`}>{member.type}</span>
              <strong className="team-amount">{member.amount}</strong>
            </button>
          ))}
        </div>
        <Link className="panel-link" href="/team">See all 16 teammates <ArrowRight size={16} /></Link>
      </section>

      <section className="panel activity-panel reveal reveal--four">
        <div className="panel-title">
          <div><span className="label">RECENTLY</span><h3>Private activity</h3></div>
          <button type="button" className="more-button" aria-label="More activity options"><MoreHorizontal size={20} /></button>
        </div>
        <div className="activity-list">
          {activity.map(({ title, meta, amount, icon: Icon, tone }) => (
            <div className="activity-row" key={title}>
              <div className={`activity-icon activity-icon--${tone}`}><Icon size={17} /></div>
              <div><strong>{title}</strong><span>{meta}</span></div>
              <b>{amount}</b>
            </div>
          ))}
        </div>
        <Link className="panel-link" href="/activity">View all activity <ArrowRight size={16} /></Link>
      </section>

      <section className="mcp-card reveal reveal--five">
        <div className="mcp-copy">
          <div className="mcp-icon"><Bot size={24} /><Zap className="mcp-zap" size={12} /></div>
          <div>
            <span className="label">FOR YOUR AI TEAMMATES</span>
            <h3>Payroll speaks MCP.</h3>
            <p>Let authorized agents check budgets, prepare payroll, and request private payments using the same rules as your human team.</p>
          </div>
        </div>
        <div className="terminal-card">
          <div className="terminal-top"><span /><span /><span /><small>MCP quick connect</small></div>
          <code><i>$</i> npx payo-mcp connect<br /><span>--team acorn-labs</span></code>
          <button type="button" onClick={copyMcp} aria-label="Copy MCP command">
            {copied ? <Check size={16} /> : <Copy size={16} />}
          </button>
        </div>
      </section>
    </div>
  );
}
