import { notFound } from "next/navigation";
import { PayoBrowserEvidenceProvider } from "@/app/vault/browser-evidence-provider";

export const dynamic = "force-dynamic";

export default function BrowserEvidenceLayout({ children }: { children: React.ReactNode }) {
  if (process.env.NODE_ENV === "production" || process.env.PAYO_BROWSER_EVIDENCE_MODE !== "1") notFound();
  return <PayoBrowserEvidenceProvider>{children}</PayoBrowserEvidenceProvider>;
}
