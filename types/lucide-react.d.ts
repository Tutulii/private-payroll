declare module "lucide-react" {
  import type { ComponentType, SVGProps } from "react";

  export type LucideProps = SVGProps<SVGSVGElement> & {
    size?: string | number;
    strokeWidth?: string | number;
  };

  export type LucideIcon = ComponentType<LucideProps>;

  export const ArrowRight: LucideIcon;
  export const ArrowLeft: LucideIcon;
  export const ArrowDownLeft: LucideIcon;
  export const ArrowUpRight: LucideIcon;
  export const Bot: LucideIcon;
  export const CalendarDays: LucideIcon;
  export const Check: LucideIcon;
  export const CheckCircle2: LucideIcon;
  export const ChevronDown: LucideIcon;
  export const CircleDollarSign: LucideIcon;
  export const CircleHelp: LucideIcon;
  export const Clock3: LucideIcon;
  export const Copy: LucideIcon;
  export const Download: LucideIcon;
  export const ExternalLink: LucideIcon;
  export const Eye: LucideIcon;
  export const EyeOff: LucideIcon;
  export const FileText: LucideIcon;
  export const Filter: LucideIcon;
  export const KeyRound: LucideIcon;
  export const LayoutDashboard: LucideIcon;
  export const Link2: LucideIcon;
  export const LoaderCircle: LucideIcon;
  export const LockKeyhole: LucideIcon;
  export const LogOut: LucideIcon;
  export const Mail: LucideIcon;
  export const Menu: LucideIcon;
  export const MoreHorizontal: LucideIcon;
  export const Plus: LucideIcon;
  export const Play: LucideIcon;
  export const PencilLine: LucideIcon;
  export const ReceiptText: LucideIcon;
  export const Search: LucideIcon;
  export const Send: LucideIcon;
  export const Settings: LucideIcon;
  export const ShieldCheck: LucideIcon;
  export const ShieldAlert: LucideIcon;
  export const Sparkles: LucideIcon;
  export const SlidersHorizontal: LucideIcon;
  export const UserPlus: LucideIcon;
  export const Users: LucideIcon;
  export const WalletCards: LucideIcon;
  export const X: LucideIcon;
  export const Zap: LucideIcon;
}
