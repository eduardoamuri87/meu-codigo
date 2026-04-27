"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { RotateCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { superRefreshAction } from "./super-refresh-action";

export function SuperRefreshButton() {
  const [isPending, startTransition] = useTransition();
  const router = useRouter();

  return (
    <>
      <Button
        type="button"
        variant="destructive"
        size="sm"
        disabled={isPending}
        onClick={() =>
          startTransition(async () => {
            try {
              await superRefreshAction();
              router.refresh();
              toast.success("Dados atualizados");
            } catch {
              toast.error("Falha ao atualizar");
            }
          })
        }
      >
        <RotateCw className={isPending ? "animate-spin" : undefined} />
        Atualizar tudo
      </Button>
      {isPending ? (
        <div
          role="status"
          aria-live="polite"
          className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 backdrop-blur-sm cursor-wait"
        >
          <div className="flex flex-col items-center gap-3 rounded-xl border border-border bg-background/95 px-6 py-5 shadow-lg">
            <RotateCw className="size-6 animate-spin text-destructive" />
            <div className="text-sm text-muted-foreground">
              Atualizando dados financeiros…
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
