"use client";

import Link from "next/link";
import { useState, useTransition } from "react";
import { toast } from "sonner";
import { MoreVertical, Pencil, Trash2 } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button, buttonVariants } from "@/components/ui/button";
import { formatCurrency, formatDateBR } from "@/lib/format";
import {
  deleteTransaction,
  toggleTransactionPaid,
} from "./transacoes/actions";

export type Row = {
  id: string;
  date: string;
  description: string;
  amount: number;
  type: "receita" | "despesa";
  paid: boolean;
  categoryId: string | null;
  categoryName: string | null;
  recurrenceId: string | null;
  parcelNumber: number | null;
  totalParcels: number | null;
};

export function TransactionsList({ rows }: { rows: Row[] }) {
  const [deleting, setDeleting] = useState<Row | null>(null);
  const [pending, startTransition] = useTransition();

  if (rows.length === 0) {
    return (
      <div className="card-soft p-12 text-center text-muted-foreground space-y-2">
        <p>Nenhuma transação neste mês.</p>
        <p className="text-xs">
          Clique em <strong>Nova transação</strong> ou pressione{" "}
          <kbd className="rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono">
            N
          </kbd>
          .
        </p>
      </div>
    );
  }

  function togglePaid(row: Row, nextPaid: boolean) {
    startTransition(async () => {
      try {
        await toggleTransactionPaid(row.id, nextPaid);
        toast.success(
          nextPaid
            ? row.type === "receita"
              ? "Marcada como recebida."
              : "Marcada como paga."
            : "Desmarcada.",
        );
      } catch {
        toast.error("Não foi possível atualizar.");
      }
    });
  }

  function handleDelete(row: Row, scope: "single" | "futures") {
    startTransition(async () => {
      try {
        await deleteTransaction(row.id, scope);
        toast.success(
          scope === "futures"
            ? "Parcelas futuras não pagas excluídas."
            : "Transação excluída.",
        );
        setDeleting(null);
      } catch {
        toast.error("Não foi possível excluir.");
      }
    });
  }

  return (
    <>
      <div className="card-soft overflow-x-auto [&_th]:h-12 [&_th]:px-5 [&_td]:py-4 [&_td]:px-5">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">Data</TableHead>
              <TableHead>Descrição</TableHead>
              <TableHead>Categoria</TableHead>
              <TableHead className="text-right w-36">Valor</TableHead>
              <TableHead className="text-center w-20">Pago?</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.id}>
                <TableCell className="tabular-nums">
                  {formatDateBR(row.date)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Link
                      href={`/transacoes/${row.id}/editar`}
                      className="hover:underline"
                    >
                      {row.description}
                    </Link>
                    {row.recurrenceId && row.parcelNumber && row.totalParcels ? (
                      <span className="text-xs rounded border px-1.5 py-0.5 bg-muted text-muted-foreground tabular-nums">
                        {row.parcelNumber}/{row.totalParcels}
                      </span>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {row.categoryName ?? "—"}
                </TableCell>
                <TableCell
                  className={`text-right tabular-nums ${
                    row.type === "receita"
                      ? "text-emerald-600"
                      : "text-rose-600"
                  }`}
                >
                  {row.type === "receita" ? "+" : "−"}
                  {formatCurrency(row.amount)}
                </TableCell>
                <TableCell className="text-center">
                  <Switch
                    checked={row.paid}
                    onCheckedChange={(v) => togglePaid(row, v)}
                    disabled={pending}
                  />
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger
                      className={buttonVariants({
                        variant: "ghost",
                        size: "icon",
                      })}
                      aria-label="Ações"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem
                        render={
                          <Link href={`/transacoes/${row.id}/editar`} />
                        }
                      >
                        <Pencil className="h-4 w-4" />
                        Editar
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        variant="destructive"
                        onClick={() => setDeleting(row)}
                      >
                        <Trash2 className="h-4 w-4" />
                        Excluir
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Excluir transação?</DialogTitle>
            <DialogDescription>
              {deleting
                ? `"${deleting.description}" de ${formatDateBR(deleting.date)}.`
                : null}
            </DialogDescription>
          </DialogHeader>
          {deleting?.recurrenceId ? (
            <div className="flex flex-col gap-2">
              <Button
                variant="destructive"
                onClick={() => handleDelete(deleting, "single")}
                disabled={pending}
              >
                Excluir só esta parcela
              </Button>
              <Button
                variant="destructive"
                onClick={() => handleDelete(deleting, "futures")}
                disabled={pending}
              >
                Excluir esta e todas as futuras não pagas
              </Button>
              <Button
                variant="ghost"
                onClick={() => setDeleting(null)}
                disabled={pending}
              >
                Cancelar
              </Button>
            </div>
          ) : (
            <DialogFooter>
              <Button
                variant="ghost"
                onClick={() => setDeleting(null)}
                disabled={pending}
              >
                Cancelar
              </Button>
              <Button
                variant="destructive"
                onClick={() => deleting && handleDelete(deleting, "single")}
                disabled={pending}
              >
                Excluir
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
