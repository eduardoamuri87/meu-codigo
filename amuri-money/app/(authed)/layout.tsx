import Link from "next/link";
import { Wallet } from "lucide-react";
import { requireUser } from "@/lib/auth/session";
import { logoutAction } from "@/lib/auth/actions";
import { Button } from "@/components/ui/button";
import { SuperRefreshButton } from "./super-refresh-button";

export default async function AuthedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await requireUser();
  const initials = user.name
    .split(" ")
    .map((s) => s[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <>
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/70 backdrop-blur">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center gap-5">
          <Link href="/" className="flex items-center gap-2 font-semibold">
            <span className="grid place-items-center size-8 rounded-lg bg-primary text-primary-foreground shadow-sm">
              <Wallet className="h-4 w-4" />
            </span>
            <span>Amuri Money</span>
          </Link>
          <nav className="flex items-center gap-1 text-sm ml-2">
            <Link
              href="/"
              className="px-3 py-1.5 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition"
            >
              Transações
            </Link>
            <Link
              href="/categorias"
              className="px-3 py-1.5 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition"
            >
              Categorias
            </Link>
            <Link
              href="/centros-de-custo"
              className="px-3 py-1.5 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground transition"
            >
              Centros de custo
            </Link>
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <SuperRefreshButton />
            <div className="hidden sm:flex items-center gap-2">
              <div className="grid place-items-center size-8 rounded-full bg-gradient-to-br from-primary to-accent-foreground text-primary-foreground text-xs font-semibold">
                {initials}
              </div>
              <span className="text-sm">{user.name}</span>
            </div>
            <form action={logoutAction}>
              <Button type="submit" variant="ghost" size="sm">
                Sair
              </Button>
            </form>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl w-full px-6 py-10 md:py-12 flex-1">
        {children}
      </main>
    </>
  );
}
