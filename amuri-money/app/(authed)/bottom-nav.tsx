"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowLeftRight, Building2, Tags } from "lucide-react";
import { cn } from "@/lib/utils";

const items = [
  { href: "/", label: "Transações", icon: ArrowLeftRight, match: "exact" },
  { href: "/categorias", label: "Categorias", icon: Tags, match: "prefix" },
  { href: "/centros-de-custo", label: "Centros", icon: Building2, match: "prefix" },
] as const;

export function BottomNav() {
  const pathname = usePathname();

  return (
    <nav className="fixed bottom-0 inset-x-0 z-40 border-t border-border/60 bg-background/95 backdrop-blur sm:hidden pb-[env(safe-area-inset-bottom)]">
      <ul className="grid grid-cols-3">
        {items.map(({ href, label, icon: Icon, match }) => {
          const active =
            match === "exact" ? pathname === href : pathname.startsWith(href);
          return (
            <li key={href}>
              <Link
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "flex flex-col items-center justify-center gap-1 py-2.5 text-xs transition",
                  active
                    ? "text-foreground"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="h-5 w-5" />
                <span>{label}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
