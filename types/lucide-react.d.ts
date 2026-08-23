declare module "lucide-react" {
  import type { ComponentType, SVGProps } from "react";

  export type LucideProps = SVGProps<SVGSVGElement> & {
    size?: string | number;
    strokeWidth?: string | number;
  };

  export type LucideIcon = ComponentType<LucideProps>;

  export const ArrowRight: LucideIcon;
  export const Bot: LucideIcon;
  export const CalendarDays: LucideIcon;
  export const Check: LucideIcon;
  export const ChevronDown: LucideIcon;
  export const CircleHelp: LucideIcon;
  export const Clock3: LucideIcon;
  export const Copy: LucideIcon;
  export const LayoutDashboard: LucideIcon;
  export const Menu: LucideIcon;
  export const MoreHorizontal: LucideIcon;
  export const Plus: LucideIcon;
  export const Send: LucideIcon;
  export const Settings: LucideIcon;
  export const ShieldCheck: LucideIcon;
  export const Sparkles: LucideIcon;
  export const Users: LucideIcon;
  export const WalletCards: LucideIcon;
  export const X: LucideIcon;
  export const Zap: LucideIcon;
}
