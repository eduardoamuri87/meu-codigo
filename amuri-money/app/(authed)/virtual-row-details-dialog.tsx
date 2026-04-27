"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatCurrency, formatDateBR } from "@/lib/format";
import type {
  IuguDetailItem,
  StripeBookItem,
  StripeDetailItem,
} from "@/lib/gateways/types";
import type { Row } from "./transactions-list";

export function VirtualRowDetailsDialog({
  row,
  onClose,
}: {
  row: Row | null;
  onClose: () => void;
}) {
  const detail = row?.virtualDetail;
  return (
    <Dialog open={row !== null} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-6xl p-6">
        <DialogHeader>
          <DialogTitle>{row?.description}</DialogTitle>
        </DialogHeader>
        {row && detail ? (
          <div className="flex flex-col gap-4">
            <div className="text-sm text-muted-foreground">
              {detail.items.length} {detail.items.length === 1 ? "item" : "itens"}
            </div>
            <div className="max-h-[65vh] overflow-auto rounded-md border [&_th]:px-4 [&_th]:h-12 [&_td]:px-4 [&_td]:py-3">
              {detail.kind === "iugu" ? (
                <IuguTable items={detail.items} total={row.amount} />
              ) : detail.kind === "stripe-books" ? (
                <StripeBooksTable items={detail.items} total={row.amount} />
              ) : (
                <StripeTable items={detail.items} total={row.amount} />
              )}
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function IuguTable({
  items,
  total,
}: {
  items: IuguDetailItem[];
  total: number;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Cliente</TableHead>
          <TableHead>Compra</TableHead>
          <TableHead>Parcela liquida em</TableHead>
          <TableHead className="text-center">Parcela</TableHead>
          <TableHead className="text-right">Valor</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell>{it.cliente}</TableCell>
            <TableCell className="tabular-nums">
              {it.compraEm ? formatDateBR(it.compraEm) : "—"}
            </TableCell>
            <TableCell className="tabular-nums">
              {formatDateBR(it.liquidaEm)}
            </TableCell>
            <TableCell className="text-center tabular-nums">
              {it.parcela}/{it.totalParcelas}
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {formatCurrency(it.valor)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
      <TableFooter>
        <TableRow>
          <TableCell colSpan={4} className="text-right">
            Total
          </TableCell>
          <TableCell className="text-right tabular-nums">
            {formatCurrency(total)}
          </TableCell>
        </TableRow>
      </TableFooter>
    </Table>
  );
}

function StripeBooksTable({
  items,
  total,
}: {
  items: StripeBookItem[];
  total: number;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Cliente</TableHead>
          <TableHead>Produto</TableHead>
          <TableHead>Cobra em</TableHead>
          <TableHead>Cai no banco</TableHead>
          <TableHead className="text-right">Valor</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell>{it.cliente}</TableCell>
            <TableCell>{it.produto}</TableCell>
            <TableCell className="tabular-nums">
              {formatDateBR(it.cobrancaEm)}
            </TableCell>
            <TableCell className="tabular-nums">
              {formatDateBR(it.disponivelEm)}
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {formatCurrency(it.valor)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
      <TableFooter>
        <TableRow>
          <TableCell colSpan={4} className="text-right">
            Total
          </TableCell>
          <TableCell className="text-right tabular-nums">
            {formatCurrency(total)}
          </TableCell>
        </TableRow>
      </TableFooter>
    </Table>
  );
}

function StripeTable({
  items,
  total,
}: {
  items: StripeDetailItem[];
  total: number;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Cliente</TableHead>
          <TableHead>Assina desde</TableHead>
          <TableHead>Cobra em</TableHead>
          <TableHead>Cai no banco</TableHead>
          <TableHead className="text-center">Restantes</TableHead>
          <TableHead className="text-right">Valor</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell>{it.cliente}</TableCell>
            <TableCell className="tabular-nums">
              {it.assinaturaDesde ? formatDateBR(it.assinaturaDesde) : "—"}
            </TableCell>
            <TableCell className="tabular-nums">
              {formatDateBR(it.cobrancaEm)}
            </TableCell>
            <TableCell className="tabular-nums">
              {formatDateBR(it.disponivelEm)}
            </TableCell>
            <TableCell className="text-center tabular-nums">
              {it.parcelasRestantes === null ? "∞" : it.parcelasRestantes}
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {formatCurrency(it.valor)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
      <TableFooter>
        <TableRow>
          <TableCell colSpan={5} className="text-right">
            Total
          </TableCell>
          <TableCell className="text-right tabular-nums">
            {formatCurrency(total)}
          </TableCell>
        </TableRow>
      </TableFooter>
    </Table>
  );
}
