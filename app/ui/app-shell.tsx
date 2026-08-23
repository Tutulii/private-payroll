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
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useStarknetWallet } from "../starknet/starknet-wallet";

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
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [toast, setToast] = useState("");

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
                <span className={starknet.isConnected && starknet.isSepolia ? "status-dot" : "status-dot status-dot--idle"} /> {starknet.networkName} <ChevronDown size={14} />
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
