import { Wallet } from "lucide-react";
import { LoginForm } from "./login-form";

export default function LoginPage() {
  return (
    <main className="min-h-dvh grid place-items-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 -z-10 pointer-events-none">
        <div className="absolute -top-40 -left-32 size-96 rounded-full bg-primary/25 blur-3xl" />
        <div className="absolute -bottom-32 -right-20 size-80 rounded-full bg-emerald-400/20 blur-3xl" />
      </div>
      <div className="flex flex-col items-center gap-4 w-full">
        <div className="flex items-center gap-2 text-lg font-semibold">
          <span className="grid place-items-center size-9 rounded-lg bg-primary text-primary-foreground shadow-sm">
            <Wallet className="h-4 w-4" />
          </span>
          Amuri Money
        </div>
        <LoginForm />
      </div>
    </main>
  );
}
