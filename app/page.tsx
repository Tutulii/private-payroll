"use client";

import {
  ArrowRight,
  Bot,
  CalendarDays,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Copy,
  LayoutDashboard,
  Menu,
  MoreHorizontal,
  Plus,
  Send,
  Settings,
  ShieldCheck,
  Sparkles,
  Users,
  WalletCards,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";

const navItems = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Payroll", icon: Send },
  { label: "People & agents", icon: Users },
  { label: "Activity", icon: Clock3 },
];

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

function MiniLogo() {
  return (
    <span className="mini-logo" aria-hidden="true">
      <span className="mini-logo__eye mini-logo__eye--left" />
      <span className="mini-logo__eye mini-logo__eye--right" />
      <span className="mini-logo__smile" />
    </span>
  );
}

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

export default function Home() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [isPayrollOpen, setPayrollOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [toast, setToast] = useState("");

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 2600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const copyMcp = async () => {
    await navigator.clipboard?.writeText("npx payo-mcp connect --team acorn-labs");
    setCopied(true);
    setToast("MCP command copied");
    window.setTimeout(() => setCopied(false), 1800);
  };

  const selectNav = (label: string) => {
    setActiveNav(label);
    setMobileNavOpen(false);
    if (label !== "Overview") setToast(`${label} workspace is ready for integration`);
  };

  return (
    <main className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? "sidebar--open" : ""}`}>
        <div className="brand">
          <MiniLogo />
          <span>Payo</span>
          <span className="brand-dot">.</span>
        </div>

        <nav className="nav-list" aria-label="Main navigation">
          {navItems.map(({ label, icon: Icon }) => (
            <button
              type="button"
              className={`nav-item ${activeNav === label ? "nav-item--active" : ""}`}
              key={label}
              onClick={() => selectNav(label)}
            >
              <Icon size={19} strokeWidth={2.2} />
              <span>{label}</span>
              {label === "People & agents" && <span className="nav-count">16</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-spacer" />

        <div className="privacy-note">
          <div className="privacy-note__icon"><ShieldCheck size={19} /></div>
          <p><strong>Private by design</strong><br />Powered by STRK20</p>
          <Sparkles className="privacy-note__spark" size={20} />
        </div>

        <nav className="nav-list nav-list--secondary" aria-label="Secondary navigation">
          <button type="button" className="nav-item" onClick={() => setToast("Help center coming soon")}>
            <CircleHelp size={19} /><span>Help</span>
          </button>
          <button type="button" className="nav-item" onClick={() => setToast("Settings coming soon")}>
            <Settings size={19} /><span>Settings</span>
          </button>
        </nav>

        <div className="profile-chip">
          <div className="avatar avatar--ink">TA</div>
          <div><strong>Tutul</strong><span>Acorn Labs</span></div>
          <MoreHorizontal size={18} />
        </div>
      </aside>

      {mobileNavOpen && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}

      <section className="workspace">
        <header className="topbar">
          <button type="button" className="mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
            <Menu size={22} />
          </button>
          <div>
            <p className="eyebrow">Sunday, August 23</p>
            <h1>Good morning, Tutul <span className="wave">👋</span></h1>
          </div>
          <div className="topbar-actions">
            <button type="button" className="network-pill" onClick={() => setToast("Connected to Starknet Mainnet")}>
              <span className="status-dot" /> Mainnet <ChevronDown size={14} />
            </button>
            <button type="button" className="icon-button" aria-label="Notifications" onClick={() => setToast("You’re all caught up")}>
              <span className="notification-dot" />
              <Clock3 size={19} />
            </button>
            <button type="button" className="button button--ink button--compact" onClick={() => setPayrollOpen(true)}>
              <Plus size={18} /> <span>New payroll</span>
            </button>
          </div>
        </header>

        <div className="content-grid">
          <section className="hero-card reveal reveal--one">
            <div className="hero-copy">
              <span className="sticker">NEXT PAYDAY</span>
              <h2>Everyone gets paid<br />in <span>4 days.</span></h2>
              <p>Your August payroll is ready for 12 people and 4 agents. Salaries stay between you and your team.</p>
              <div className="hero-actions">
                <button type="button" className="button button--ink" onClick={() => setPayrollOpen(true)}>
                  Review payroll <ArrowRight size={18} />
                </button>
                <button type="button" className="text-button" onClick={() => setToast("Payday moved to August 27")}>Aug 27 <CalendarDays size={16} /></button>
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
            <button type="button" className="button button--cream button--wide" onClick={() => setToast("Treasury funding flow opened")}>
              <WalletCards size={18} /> Add private funds
            </button>
          </section>

          <section className="panel team-panel reveal reveal--three">
            <div className="panel-title">
              <div><span className="label">YOUR CREW</span><h3>People & agents</h3></div>
              <button type="button" className="circle-add" aria-label="Add team member" onClick={() => setToast("Invite flow opened")}><Plus size={19} /></button>
            </div>
            <div className="team-list">
              {team.map((member, index) => (
                <button type="button" className="team-row" key={member.name} onClick={() => setToast(`${member.name} selected`)}>
                  <div className={`avatar avatar--${member.tone}`}>
                    {member.type === "agent" ? <Bot size={18} /> : member.initials}
                    <span className="online-dot" />
                  </div>
                  <div className="team-info"><strong>{member.name}</strong><span>{member.role}</span></div>
                  <span className={`type-pill ${member.type === "agent" ? "type-pill--agent" : ""}`}>{member.type}</span>
                  <strong className="team-amount">{member.amount}</strong>
                  <span className="row-number">0{index + 1}</span>
                </button>
              ))}
            </div>
            <button type="button" className="panel-link" onClick={() => selectNav("People & agents")}>See all 16 teammates <ArrowRight size={16} /></button>
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
            <button type="button" className="panel-link" onClick={() => selectNav("Activity")}>View all activity <ArrowRight size={16} /></button>
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
      </section>

      {isPayrollOpen && (
        <div className="modal-wrap" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setPayrollOpen(false)}>
          <section className="payroll-modal" role="dialog" aria-modal="true" aria-labelledby="payroll-title">
            <div className="modal-top">
              <div className="modal-illustration"><span>PAY</span><ShieldCheck size={23} /></div>
              <button type="button" className="modal-close" onClick={() => setPayrollOpen(false)} aria-label="Close payroll"><X size={20} /></button>
            </div>
            <span className="label">AUGUST 2026</span>
            <h2 id="payroll-title">Ready to run payroll?</h2>
            <p>Review the batch before anything is signed. Individual amounts and recipients are handled privately through STRK20.</p>
            <div className="modal-summary">
              <div><span>Recipients</span><strong>12 humans + 4 agents</strong></div>
              <div><span>Total</span><strong>$12,640 USDC</strong></div>
              <div><span>Payday</span><strong>August 27</strong></div>
            </div>
            <div className="privacy-callout"><ShieldCheck size={20} /><span><strong>Private payment batch</strong><br />Only you and each recipient can see their payment details.</span></div>
            <button type="button" className="button button--ink button--wide" onClick={() => { setPayrollOpen(false); setToast("Payroll review opened"); }}>
              Continue to review <ArrowRight size={18} />
            </button>
            <button type="button" className="modal-cancel" onClick={() => setPayrollOpen(false)}>I’ll do this later</button>
          </section>
        </div>
      )}

      {toast && <div className="toast" role="status"><Check size={17} /> {toast}</div>}
    </main>
  );
}
