import type { Metadata } from "next";
import AppShell from "./ui/app-shell";
import "./globals.css";

export const metadata: Metadata = {
  title: "Payo — Private payroll for every kind of team",
  description: "Private payroll for people and AI agents, powered by STRK20.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body><AppShell>{children}</AppShell></body>
    </html>
  );
}
