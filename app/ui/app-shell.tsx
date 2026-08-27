"use client";

import {
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
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
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useStarknetWallet } from "../starknet/starknet-wallet";
import { usePayoVault } from "../vault/payo-vault";
import {
  parsePendingPayrollSubmission,
} from "@/lib/client/payroll-execution";
import { recoverConfirmedPayrollFromBrowser } from "@/lib/client/confirmed-payroll-recovery";

const navItems = [
  { label: "Overview", icon: LayoutDashboard, href: "/" },
  { label: "Payroll", icon: Send, href: "/payroll" },
  { label: "People & agents", icon: Users, href: "/team" },
  { label: "Activity", icon: Clock3, href: "/activity" },
  { label: "Connect wallet", icon: WalletCards, href: "/wallet" },
];

const pageTitles: Record<string, { eyebrow: string; title: string }> = {
  "/": { eyebrow: "Sunday, August 23", title: "Good morning, Tutul" },
  "/payroll": { eyebrow: "Payroll workspace", title: "Payday, made private" },
  "/team": { eyebrow: "Your organization", title: "People & agents" },
  "/activity": { eyebrow: "Private records", title: "Activity & receipts" },
  "/wallet": { eyebrow: "Wallet & identity", title: "Connect your wallet" },
};

type AppShellContextValue = {
  openPayroll: () => void;
  notify: (message: string) => void;
};

const AppShellContext = createContext<AppShellContextValue | null>(null);

export function useAppShell() {
  const context = useContext(AppShellContext);
  if (!context) throw new Error("useAppShell must be used within AppShell");
  return context;
}

function MiniLogo() {
  return (
    <span className="mini-logo" aria-hidden="true">
      <span className="mini-logo__eye mini-logo__eye--left" />
      <span className="mini-logo__eye mini-logo__eye--right" />
      <span className="mini-logo__smile" />
    </span>
  );
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const starknet = useStarknetWallet();
  const { reconcilePayrollTransaction } = starknet;
  const vault = usePayoVault();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [toast, setToast] = useState("");
  const proofRecoveryRunsRef = useRef(new Set<string>());
  const proofRecoveryOrganizationRef = useRef("");

  const title = pageTitles[pathname] ?? pageTitles["/"];
  const openPayroll = useCallback(() => {
    if (pathname === "/payroll") {
      window.history.replaceState(null, "", "/payroll#private-payroll");
      document.getElementById("private-payroll")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    router.push("/payroll#private-payroll");
  }, [pathname, router]);
  const contextValue = useMemo(
    () => ({ openPayroll, notify: (message: string) => setToast(message) }),
    [openPayroll],
  );

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 2600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    if (pathname.startsWith("/payo-browser-evidence")) return;
    const client = vault.client;
    const session = vault.session;
    if (!client || !session) {
      proofRecoveryRunsRef.current.clear();
      proofRecoveryOrganizationRef.current = "";
      return;
    }
    if (proofRecoveryOrganizationRef.current !== session.organizationId) {
      proofRecoveryRunsRef.current.clear();
      proofRecoveryOrganizationRef.current = session.organizationId;
    }

    let cancelled = false;
    let polling = false;
    const recoverMissingProofJobs = async () => {
      if (polling || cancelled) return;
      polling = true;
      try {
        const storageKey = `payo:pending-settlement:v1:${session.organizationId}`;
        const serialized = window.localStorage.getItem(storageKey);
        let pending = null;
        if (serialized) {
          try {
            const parsed = parsePendingPayrollSubmission(JSON.parse(serialized));
            if (parsed.organizationId === session.organizationId) pending = parsed;
          } catch {
            // Keep corrupt recovery evidence untouched for explicit support recovery.
          }
        }
        const { runs } = await client.listPayrollRuns(session.organizationId);
        const candidates = runs.flatMap((run) => {
          if (
            typeof run.id !== "string"
            || run.state !== "confirmed"
            || typeof run.transactionHash !== "string"
            || proofRecoveryRunsRef.current.has(run.id)
          ) return [];
          return [{ runId: run.id, transactionHash: run.transactionHash }];
        });
        for (const { runId, transactionHash } of candidates) {
          if (cancelled) return;
          proofRecoveryRunsRef.current.add(runId);
          try {
            const recovered = await recoverConfirmedPayrollFromBrowser({
              client,
              organizationId: session.organizationId,
              runId,
              indexedTransactionHash: transactionHash,
              principal: session.principal,
              pendingSubmission: pending?.runId === runId ? pending : null,
              persistPendingSubmission: (next) => {
                if (next) window.localStorage.setItem(storageKey, JSON.stringify(next));
                else window.localStorage.removeItem(storageKey);
              },
            });
            window.dispatchEvent(new CustomEvent("payo:payroll-proof-recovered", {
              detail: {
                runId,
                transactionHash: recovered.transactionHash,
                verificationQueued: recovered.verificationQueued,
                proofDeliveryWarning: recovered.proofDeliveryWarning,
              },
            }));
            // This releases Ready's browser lock synchronously. Private-balance
            // refresh remains best-effort and must never hold Activity loading.
            void reconcilePayrollTransaction(recovered.transactionHash);
            if (!recovered.verificationQueued) {
              window.setTimeout(() => proofRecoveryRunsRef.current.delete(runId), 15_000);
            }
            if (!cancelled) setToast(recovered.verificationQueued
              ? "Confirmed payroll proof verification queued automatically"
              : "Payroll confirmed; encrypted proof recovery will retry automatically");
          } catch (error) {
            const permanentExpiry = error instanceof Error
              && error.message.includes("missed its on-chain proof-delivery window");
            if (!permanentExpiry) {
              window.setTimeout(() => proofRecoveryRunsRef.current.delete(runId), 15_000);
            }
          }
        }
      } finally {
        polling = false;
      }
    };
    const initial = window.setTimeout(() => void recoverMissingProofJobs(), 0);
    const interval = window.setInterval(() => void recoverMissingProofJobs(), 5_000);
    return () => {
      cancelled = true;
      window.clearTimeout(initial);
      window.clearInterval(interval);
    };
  }, [pathname, reconcilePayrollTransaction, vault.client, vault.session]);

  useEffect(() => {
    const transaction = starknet.transaction;
    const client = vault.client;
    const session = vault.session;
    if (
      !client
      || !session
      || transaction?.kind !== "payroll"
      || (transaction.stage !== "wallet" && transaction.stage !== "confirming")
      || !transaction.startedAt
    ) return;

    let cancelled = false;
    let polling = false;
    const reconcileIndexedPayroll = async () => {
      if (cancelled || polling) return;
      polling = true;
      try {
        const storageKey = `payo:pending-settlement:v1:${session.organizationId}`;
        const serialized = window.localStorage.getItem(storageKey);
        let pendingRunId = "";
        if (serialized) {
          try {
            pendingRunId = parsePendingPayrollSubmission(JSON.parse(serialized)).runId;
          } catch {
            // The server timestamp fallback below remains bounded to this wallet request.
          }
        }
        const { settlements } = await client.listSettlements(session.organizationId);
        const recovered = settlements.find((settlement) => {
          if (
            settlement.workflowType !== "payroll"
            || !["confirmed", "finalized", "reconciled"].includes(settlement.state)
            || typeof settlement.transactionHash !== "string"
          ) return false;
          if (transaction.hash) return BigInt(settlement.transactionHash) === BigInt(transaction.hash);
          if (pendingRunId) return settlement.runId === pendingRunId;
          const createdAt = new Date(settlement.createdAt).getTime();
          return Number.isFinite(createdAt)
            && createdAt >= transaction.startedAt! - 60_000
            && createdAt <= transaction.startedAt! + 60_000;
        });
        const recoveredHash = recovered?.transactionHash;
        if (typeof recoveredHash === "string" && !cancelled) {
          await reconcilePayrollTransaction(recoveredHash);
        }
      } catch {
        // A temporary API failure must not replace the existing recovery UI.
      } finally {
        polling = false;
      }
    };
    const initial = window.setTimeout(() => void reconcileIndexedPayroll(), 0);
    const interval = window.setInterval(() => void reconcileIndexedPayroll(), 5_000);
    return () => {
      cancelled = true;
      window.clearTimeout(initial);
      window.clearInterval(interval);
    };
  }, [reconcilePayrollTransaction, starknet.transaction, vault.client, vault.session]);

  return (
    <AppShellContext.Provider value={contextValue}>
      <main className="app-shell">
        <aside className={`sidebar ${mobileNavOpen ? "sidebar--open" : ""}`}>
          <Link href="/" className="brand" onClick={() => setMobileNavOpen(false)}>
            <MiniLogo />
            <span>Payo</span>
            <span className="brand-dot">.</span>
          </Link>

          <nav className="nav-list" aria-label="Main navigation">
            {navItems.map(({ label, icon: Icon, href }) => {
              const active = pathname === href;
              return (
                <Link
                  className={`nav-item ${active ? "nav-item--active" : ""}`}
                  href={href}
                  key={label}
                  onClick={() => setMobileNavOpen(false)}
                >
                  <Icon size={19} strokeWidth={2.2} />
                  <span>{label}</span>
                  {label === "People & agents" && <span className="nav-count">16</span>}
                </Link>
              );
            })}
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
            <div className="topbar-title">
              <p className="eyebrow">{title.eyebrow}</p>
              <h1>{title.title} {pathname === "/" && <span className="wave">👋</span>}</h1>
            </div>
            <div className="topbar-actions">
              <Link className="network-pill" href="/wallet" title={starknet.isConnected ? `Connected to ${starknet.networkName}` : "Connect Ready wallet"}>
                <span className={starknet.isConnected && starknet.isMainnet ? "status-dot" : "status-dot status-dot--idle"} /> {starknet.networkName} <ChevronDown size={14} />
              </Link>
              <button type="button" className="icon-button" aria-label="Notifications" onClick={() => setToast("You’re all caught up")}>
                <span className="notification-dot" />
                <Clock3 size={19} />
              </button>
              <button type="button" className="button button--ink button--compact" onClick={openPayroll}>
                <Plus size={18} /> <span>New payroll</span>
              </button>
            </div>
          </header>

          {children}
        </section>

        {toast && <div className="toast" role="status"><Check size={17} /> {toast}</div>}
      </main>
    </AppShellContext.Provider>
  );
}
