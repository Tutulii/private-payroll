"use client";

import {
  Bot,
  Check,
  Copy,
  KeyRound,
  Mail,
  MoreHorizontal,
  Plus,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  UserPlus,
  WalletCards,
  Zap,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useAppShell } from "../ui/app-shell";

type MemberKind = "Human" | "Agent";

const members: Array<{
  name: string;
  role: string;
  kind: MemberKind;
  amount: string;
  cadence: string;
  initials: string;
  tone: string;
  ready: boolean;
}> = [
  { name: "Maya Chen", role: "Product designer", kind: "Human", amount: "$3,200", cadence: "Monthly", initials: "MC", tone: "coral", ready: true },
  { name: "Theo Brooks", role: "Cairo engineer", kind: "Human", amount: "$4,100", cadence: "Monthly", initials: "TB", tone: "blue", ready: true },
  { name: "Amara Jones", role: "Community lead", kind: "Human", amount: "$2,450", cadence: "Monthly", initials: "AJ", tone: "green", ready: true },
  { name: "Sol Rivera", role: "Visual artist", kind: "Human", amount: "$1,750", cadence: "Monthly", initials: "SR", tone: "yellow", ready: false },
  { name: "Scout", role: "Research agent", kind: "Agent", amount: "$420", cadence: "Usage cap", initials: "SC", tone: "yellow", ready: true },
  { name: "Patch", role: "QA agent", kind: "Agent", amount: "$280", cadence: "Usage cap", initials: "PA", tone: "green", ready: true },
  { name: "Milo", role: "Support agent", kind: "Agent", amount: "$240", cadence: "Usage cap", initials: "MI", tone: "blue", ready: true },
  { name: "Ledger", role: "Accounting agent", kind: "Agent", amount: "$200", cadence: "Usage cap", initials: "LE", tone: "coral", ready: true },
];

const teamFilters = ["Everyone", "Humans", "Agents"] as const;

export default function TeamPage() {
  const { notify } = useAppShell();
  const [filter, setFilter] = useState<(typeof teamFilters)[number]>("Everyone");
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);

  const visibleMembers = useMemo(() => {
    return members.filter((member) => {
      const matchesKind = filter === "Everyone" || (filter === "Humans" && member.kind === "Human") || (filter === "Agents" && member.kind === "Agent");
      const matchesQuery = `${member.name} ${member.role}`.toLowerCase().includes(query.toLowerCase());
      return matchesKind && matchesQuery;
    });
  }, [filter, query]);

  const copyToken = async () => {
    await navigator.clipboard?.writeText("payo://mcp/acorn-labs/connect");
    setCopied(true);
    notify("Agent connection copied");
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="product-page team-page">
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--green">ONE TEAM</span>
          <h2>People and agents,<br /><em>paid together.</em></h2>
          <p>Set compensation, private payout identities, and clear permissions for every kind of contributor.</p>
        </div>
        <div className="page-heading__actions">
          <button type="button" className="button button--soft" onClick={() => notify("Invite link copied")}><Mail size={17} /> Invite link</button>
          <button type="button" className="button button--ink" onClick={() => notify("Add teammate flow opened")}><UserPlus size={17} /> Add teammate</button>
        </div>
      </section>

      <section className="team-story-card reveal reveal--two">
        <div className="team-story__copy">
          <span className="label">TEAM SNAPSHOT</span>
          <h3>16 contributors.<br />One private payday.</h3>
          <p>People receive salaries. Agents receive operating budgets. Payo gives both a private balance without exposing their activity to the rest of the team.</p>
          <div className="team-story__legend"><span><i className="legend-human" />12 humans</span><span><i className="legend-agent" />4 agents</span></div>
        </div>

        <div className="crew-art" aria-hidden="true">
          <span className="crew-spark crew-spark--one">✦</span><span className="crew-spark crew-spark--two">✦</span>
          <div className="crew-person">
            <div className="crew-head"><i /><i /><b /></div>
            <div className="crew-body">HUMAN</div>
            <span className="crew-arm crew-arm--right" />
            <span className="crew-leg crew-leg--one" /><span className="crew-leg crew-leg--two" />
          </div>
          <div className="crew-link"><span>+ PAY</span></div>
          <div className="crew-bot">
            <span className="crew-antenna" />
            <div className="crew-bot__screen"><i /><i /><b /></div>
            <strong>AGENT</strong>
            <span className="crew-arm crew-arm--left" />
            <span className="crew-leg crew-leg--one" /><span className="crew-leg crew-leg--two" />
          </div>
        </div>

        <div className="team-story__stats">
          <div><span>Monthly payroll</span><strong>$12,640</strong></div>
          <div><span>Privacy-ready</span><strong>15 <small>/ 16</small></strong></div>
          <div><span>Agent allowance</span><strong>$1,140</strong></div>
        </div>
      </section>

      <section className="directory-section reveal reveal--three">
        <div className="directory-top">
          <div><span className="label">DIRECTORY</span><h3>Meet the crew</h3></div>
          <div className="directory-tools">
            <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search the crew" aria-label="Search team" /></label>
            <button type="button" className="square-tool" aria-label="Directory filters" onClick={() => notify("More filters coming soon")}><SlidersHorizontal size={17} /></button>
          </div>
        </div>
        <div className="filter-tabs team-tabs" role="tablist" aria-label="Filter team">
          {teamFilters.map((item) => (
            <button type="button" role="tab" aria-selected={filter === item} className={filter === item ? "filter-tab filter-tab--active" : "filter-tab"} key={item} onClick={() => setFilter(item)}>
              {item} <span>{item === "Everyone" ? 16 : item === "Humans" ? 12 : 4}</span>
            </button>
          ))}
        </div>

        <div className="member-grid">
          {visibleMembers.map((member) => (
            <article className="member-card" key={member.name}>
              <button type="button" className="member-more" aria-label={`More options for ${member.name}`}><MoreHorizontal size={18} /></button>
              <div className={`member-avatar avatar--${member.tone}`}>
                {member.kind === "Agent" ? <Bot size={24} /> : member.initials}
                <span className={member.ready ? "member-status" : "member-status member-status--pending"} />
              </div>
              <div className="member-name"><h4>{member.name}</h4><span className={member.kind === "Agent" ? "kind-tag kind-tag--agent" : "kind-tag"}>{member.kind}</span></div>
              <p>{member.role}</p>
              <div className="member-pay"><span><small>Compensation</small><strong>{member.amount}</strong></span><em>{member.cadence}</em></div>
              <button type="button" className="member-open" onClick={() => notify(`${member.name} profile opened`)}>View profile <span>→</span></button>
            </article>
          ))}
          <button type="button" className="member-card member-card--add" onClick={() => notify("Add teammate flow opened")}>
            <span><Plus size={22} /></span><strong>Add someone new</strong><small>Human or AI agent</small>
          </button>
        </div>
        {visibleMembers.length === 0 && <div className="directory-empty"><Search size={24} /><strong>No teammates found</strong><span>Try another name or filter.</span></div>}
      </section>

      <section className="agent-access-card reveal reveal--four">
        <div className="agent-access__intro">
          <div className="agent-access__icon"><Bot size={25} /><Zap size={12} /></div>
          <div><span className="label">MCP ACCESS</span><h3>Give agents a key—not the keys.</h3><p>Agents can prepare work within precise limits. Human approval still controls every private payroll execution.</p></div>
        </div>
        <div className="scope-list">
          <span><Check size={13} /> Read treasury balance</span>
          <span><Check size={13} /> Prepare payroll draft</span>
          <span><Check size={13} /> Request payment</span>
          <span className="scope-off"><KeyRound size={13} /> Execute payment</span>
        </div>
        <div className="agent-connect">
          <div><WalletCards size={16} /><span><small>Team connection</small><strong>payo://mcp/acorn-labs</strong></span></div>
          <button type="button" onClick={copyToken} aria-label="Copy agent connection">{copied ? <Check size={16} /> : <Copy size={16} />}</button>
        </div>
        <div className="access-footnote"><ShieldCheck size={16} /> 4 agents connected · Last policy review 2 days ago <Sparkles size={14} /></div>
      </section>
    </div>
  );
}
