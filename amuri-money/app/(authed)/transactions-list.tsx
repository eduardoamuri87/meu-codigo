"use client";

import { useMemo, useState, useTransition } from "react";
import { toast } from "sonner";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronDown,
  ChevronRight,
  Layers,
  Link2Off,
  MoreVertical,
  Pencil,
  Plus,
  Repeat,
  ClipboardPaste,
  Trash2,
  Unlink,
} from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Combobox } from "@/components/ui/combobox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { formatCurrency, formatDateBR, parseDecimalBR } from "@/lib/format";
import type { Category, CostCenter } from "@/lib/db/schema";
import type { VirtualRowDetail } from "@/lib/gateways/types";
import {
  addChild,
  convertToRecurrent,
  deleteTransaction,
  detachFromParent,
  importChildrenFromText,
  makeParent,
  toggleTransactionPaid,
  unlinkRecurrence,
  unmakeParent,
  updateRecurrentTransaction,
  updateTransactionField,
  type EditableField,
  type RecurrentEditPatch,
  type RecurrentEditScope,
  type UnmakeParentScope,
} from "./transacoes/actions";
import { createCategoryInline } from "./categorias/actions";
import { createCostCenterInline } from "./centros-de-custo/actions";
import { VirtualRowDetailsDialog } from "./virtual-row-details-dialog";

export type Row = {
  id: string;
  date: string;
  description: string;
  amount: number;
  type: "receita" | "despesa";
  paid: boolean;
  categoryId: string | null;
  categoryName: string | null;
  costCenterId: string | null;
  costCenterName: string | null;
  recurrenceId: string | null;
  parcelNumber: number | null;
  totalParcels: number | null;
  dayOfMonth: number | null;
  parentId: string | null;
  isParent: boolean;
  childSum: number;
  virtual?: boolean;
  virtualDetail?: VirtualRowDetail;
};

type SortKey =
  | "date"
  | "description"
  | "categoryName"
  | "costCenterName"
  | "amount"
  | "paid";
type SortDir = "asc" | "desc";
type EditingCell = { rowId: string; field: EditableField } | null;

const NO_CATEGORY = "__none__";

function compareRows(a: Row, b: Row, key: SortKey): number {
  switch (key) {
    case "date":
      return a.date.localeCompare(b.date);
    case "description":
      return a.description.localeCompare(b.description, "pt-BR");
    case "categoryName":
      return (a.categoryName ?? "").localeCompare(
        b.categoryName ?? "",
        "pt-BR",
      );
    case "costCenterName":
      return (a.costCenterName ?? "").localeCompare(
        b.costCenterName ?? "",
        "pt-BR",
      );
    case "amount":
      return a.amount - b.amount;
    case "paid":
      return (a.paid ? 1 : 0) - (b.paid ? 1 : 0);
  }
}

export function TransactionsList({
  rows,
  categories,
  costCenters,
}: {
  rows: Row[];
  categories: Category[];
  costCenters: CostCenter[];
}) {
  const [deleting, setDeleting] = useState<Row | null>(null);
  const [converting, setConverting] = useState<Row | null>(null);
  const [editingRecurrent, setEditingRecurrent] = useState<Row | null>(null);
  const [unlinking, setUnlinking] = useState<Row | null>(null);
  const [unmaking, setUnmaking] = useState<Row | null>(null);
  const [importingTo, setImportingTo] = useState<Row | null>(null);
  const [addingChildTo, setAddingChildTo] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [editing, setEditing] = useState<EditingCell>(null);
  const [scopePrompt, setScopePrompt] = useState<{
    row: Row;
    field: "description" | "amount" | "categoryId" | "costCenterId";
    rawValue: string;
  } | null>(null);
  const [detailRow, setDetailRow] = useState<Row | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("date");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [pending, startTransition] = useTransition();

  type RenderItem =
    | { kind: "row"; row: Row; depth: 0 | 1 }
    | { kind: "add-child"; parentId: string; type: "receita" | "despesa"; date: string };

  const renderItems: RenderItem[] = useMemo(() => {
    const virtual = rows.filter((r) => r.virtual);
    const normal = rows.filter((r) => !r.virtual);
    const ids = new Set(normal.map((r) => r.id));
    const childrenByParent = new Map<string, Row[]>();
    for (const r of normal) {
      if (r.parentId && ids.has(r.parentId)) {
        const arr = childrenByParent.get(r.parentId) ?? [];
        arr.push(r);
        childrenByParent.set(r.parentId, arr);
      }
    }
    for (const arr of childrenByParent.values()) {
      arr.sort((a, b) => a.date.localeCompare(b.date));
    }
    const topLevels = normal.filter(
      (r) => !r.parentId || !ids.has(r.parentId),
    );
    topLevels.sort((a, b) => {
      const d = compareRows(a, b, sortKey);
      return sortDir === "asc" ? d : -d;
    });
    const items: RenderItem[] = [];
    for (const r of virtual) items.push({ kind: "row", row: r, depth: 0 });
    for (const r of topLevels) {
      items.push({ kind: "row", row: r, depth: 0 });
      if (r.isParent && expanded.has(r.id)) {
        const children = childrenByParent.get(r.id) ?? [];
        for (const c of children) items.push({ kind: "row", row: c, depth: 1 });
        items.push({
          kind: "add-child",
          parentId: r.id,
          type: r.type,
          date: r.date,
        });
      }
    }
    return items;
  }, [rows, sortKey, sortDir, expanded]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  if (rows.length === 0) {
    return (
      <div className="card-soft p-12 text-center text-muted-foreground space-y-2">
        <p>Nenhuma transação neste mês.</p>
        <p className="text-xs">
          Clique em <strong>Nova transação</strong> para adicionar.
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

  function handleUnlink(row: Row) {
    startTransition(async () => {
      try {
        await unlinkRecurrence(row.id);
        toast.success("Recorrência desvinculada.");
        setUnlinking(null);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível desvincular.",
        );
      }
    });
  }

  function handleEditRecurrent(
    row: Row,
    scope: RecurrentEditScope,
    patch: RecurrentEditPatch,
  ) {
    startTransition(async () => {
      try {
        await updateRecurrentTransaction(row.id, scope, patch);
        toast.success(
          scope === "single"
            ? "Transação atualizada."
            : scope === "futures"
              ? "Esta e as próximas não pagas atualizadas."
              : "Todas as parcelas não pagas atualizadas.",
        );
        setEditingRecurrent(null);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível atualizar.",
        );
      }
    });
  }

  function handleConvert(
    row: Row,
    totalParcelsOrForever: number | "forever",
    dayOfMonth: number,
  ) {
    startTransition(async () => {
      try {
        await convertToRecurrent(row.id, totalParcelsOrForever, dayOfMonth);
        toast.success("Transação transformada em recorrente.");
        setConverting(null);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível converter.",
        );
      }
    });
  }

  function commitField(row: Row, field: EditableField, rawValue: string) {
    if (
      row.recurrenceId &&
      (field === "description" ||
        field === "amount" ||
        field === "categoryId" ||
        field === "costCenterId")
    ) {
      setScopePrompt({ row, field, rawValue });
      return;
    }
    startTransition(async () => {
      try {
        await updateTransactionField(row.id, field, rawValue);
        toast.success("Atualizado.");
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Não foi possível atualizar.");
      } finally {
        setEditing(null);
      }
    });
  }

  function handleScopePromptChoose(scope: RecurrentEditScope) {
    const prompt = scopePrompt;
    if (!prompt) return;
    startTransition(async () => {
      try {
        if (scope === "single") {
          await updateTransactionField(prompt.row.id, prompt.field, prompt.rawValue);
        } else {
          const patch: RecurrentEditPatch = {};
          if (prompt.field === "description") {
            patch.description = prompt.rawValue.trim();
          } else if (prompt.field === "amount") {
            const n = parseDecimalBR(prompt.rawValue);
            if (n === null) throw new Error("Valor inválido.");
            patch.amount = n;
          } else if (prompt.field === "categoryId") {
            patch.categoryId =
              !prompt.rawValue || prompt.rawValue === NO_CATEGORY
                ? null
                : prompt.rawValue;
          } else {
            patch.costCenterId =
              !prompt.rawValue || prompt.rawValue === NO_CATEGORY
                ? null
                : prompt.rawValue;
          }
          await updateRecurrentTransaction(prompt.row.id, scope, patch);
        }
        toast.success(
          scope === "single"
            ? "Atualizado."
            : scope === "futures"
              ? "Esta e as próximas não pagas atualizadas."
              : "Todas as parcelas não pagas atualizadas.",
        );
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível atualizar.",
        );
      } finally {
        setScopePrompt(null);
        setEditing(null);
      }
    });
  }

  function isEditing(row: Row, field: EditableField) {
    return editing?.rowId === row.id && editing.field === field;
  }

  function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function handleMakeParent(row: Row) {
    startTransition(async () => {
      try {
        await makeParent(row.id);
        setExpanded((prev) => new Set(prev).add(row.id));
        toast.success("Transação virou agrupador.");
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível.",
        );
      }
    });
  }

  function handleUnmakeParent(row: Row, scope: UnmakeParentScope) {
    startTransition(async () => {
      try {
        await unmakeParent(row.id, scope);
        toast.success(
          scope === "delete"
            ? "Agrupador e itens excluídos."
            : "Agrupador desfeito; itens viraram avulsos.",
        );
        setUnmaking(null);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível.",
        );
      }
    });
  }

  function handleDetachFromParent(row: Row) {
    startTransition(async () => {
      try {
        await detachFromParent(row.id);
        toast.success("Item desvinculado do agrupador.");
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível.",
        );
      }
    });
  }

  return (
    <>
      <div className="card-soft overflow-x-auto [&_th]:h-12 [&_th]:px-5 [&_td]:py-4 [&_td]:px-5">
        <Table>
          <TableHeader>
            <TableRow>
              <SortableHead
                label="Data"
                sortKey="date"
                activeKey={sortKey}
                activeDir={sortDir}
                onToggle={toggleSort}
                className="w-32"
              />
              <SortableHead
                label="Descrição"
                sortKey="description"
                activeKey={sortKey}
                activeDir={sortDir}
                onToggle={toggleSort}
              />
              <SortableHead
                label="Categoria"
                sortKey="categoryName"
                activeKey={sortKey}
                activeDir={sortDir}
                onToggle={toggleSort}
              />
              <SortableHead
                label="Centro de custo"
                sortKey="costCenterName"
                activeKey={sortKey}
                activeDir={sortDir}
                onToggle={toggleSort}
              />
              <SortableHead
                label="Valor"
                sortKey="amount"
                activeKey={sortKey}
                activeDir={sortDir}
                onToggle={toggleSort}
                className="w-40"
                align="end"
              />
              <SortableHead
                label="Pago?"
                sortKey="paid"
                activeKey={sortKey}
                activeDir={sortDir}
                onToggle={toggleSort}
                className="w-20"
                align="center"
              />
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {renderItems.map((item) => {
              if (item.kind === "add-child") {
                return (
                  <AddChildRow
                    key={`add:${item.parentId}`}
                    parentId={item.parentId}
                    parentType={item.type}
                    parentDate={item.date}
                    categories={categories}
                    costCenters={costCenters}
                    isOpen={addingChildTo === item.parentId}
                    onOpen={() => setAddingChildTo(item.parentId)}
                    onClose={() => setAddingChildTo(null)}
                  />
                );
              }
              const row = item.row;
              const isParentRow = !row.virtual && row.isParent;
              const isChildRow = item.depth === 1;
              const displayAmount = isParentRow ? row.childSum : row.amount;
              const rowClassName = row.virtual
                ? "bg-yellow-50/80 hover:bg-yellow-100/80 cursor-pointer"
                : isParentRow
                  ? "bg-rose-100/70 hover:bg-rose-200/70"
                  : isChildRow
                    ? "bg-muted/20"
                    : "";
              return (
                <TableRow
                  key={row.id}
                  className={rowClassName}
                  onClick={
                    row.virtual ? () => setDetailRow(row) : undefined
                  }
                >
                  <TableCell className="tabular-nums">
                    {row.virtual ? (
                      "—"
                    ) : isEditing(row, "date") ? (
                      <InlineInput
                        type="date"
                        initial={row.date}
                        pending={pending}
                        onCommit={(v) => commitField(row, "date", v)}
                        onCancel={() => setEditing(null)}
                      />
                    ) : (
                      <CellButton
                        onClick={() => setEditing({ rowId: row.id, field: "date" })}
                      >
                        {formatDateBR(row.date)}
                      </CellButton>
                    )}
                  </TableCell>
                  <TableCell>
                    <div
                      className={`flex items-center gap-2 ${isChildRow ? "pl-6" : ""}`}
                    >
                      {isParentRow ? (
                        <button
                          type="button"
                          onClick={() => toggleExpanded(row.id)}
                          aria-label={
                            expanded.has(row.id) ? "Colapsar" : "Expandir"
                          }
                          className="size-5 grid place-items-center rounded hover:bg-muted shrink-0 cursor-pointer"
                        >
                          {expanded.has(row.id) ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      ) : null}
                      {row.virtual ? (
                        <span>{row.description}</span>
                      ) : isEditing(row, "description") ? (
                        <InlineInput
                          type="text"
                          initial={row.description}
                          pending={pending}
                          onCommit={(v) => commitField(row, "description", v)}
                          onCancel={() => setEditing(null)}
                        />
                      ) : (
                        <CellButton
                          onClick={() =>
                            setEditing({ rowId: row.id, field: "description" })
                          }
                        >
                          {row.description}
                        </CellButton>
                      )}
                      {row.recurrenceId && row.parcelNumber ? (
                        <span
                          className="text-xs rounded border px-1.5 py-0.5 bg-muted text-muted-foreground tabular-nums"
                          title={
                            row.totalParcels
                              ? `Parcela ${row.parcelNumber} de ${row.totalParcels}`
                              : `Parcela ${row.parcelNumber} — recorrência sem fim`
                          }
                        >
                          {row.totalParcels
                            ? `${row.parcelNumber}/${row.totalParcels}`
                            : `${row.parcelNumber}/∞`}
                        </span>
                      ) : null}
                      {row.virtual ? (
                        <span className="text-xs rounded border px-1.5 py-0.5 bg-muted text-muted-foreground">
                          auto
                        </span>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {row.virtual ? (
                      (row.categoryName ?? "—")
                    ) : isParentRow ? (
                      <span className="text-muted-foreground/60">—</span>
                    ) : isEditing(row, "categoryId") ? (
                      <InlineCategorySelect
                        rowType={row.type}
                        categories={categories.filter((c) => c.type === row.type)}
                        pending={pending}
                        onCommit={(v) => commitField(row, "categoryId", v)}
                        onCancel={() => setEditing(null)}
                      />
                    ) : (
                      <CellButton
                        onClick={() =>
                          setEditing({ rowId: row.id, field: "categoryId" })
                        }
                      >
                        {row.categoryName ?? "—"}
                      </CellButton>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {row.virtual || row.type === "receita" ? (
                      "—"
                    ) : isParentRow ? (
                      <span className="text-muted-foreground/60">—</span>
                    ) : isEditing(row, "costCenterId") ? (
                      <InlineCostCenterSelect
                        costCenters={costCenters}
                        pending={pending}
                        onCommit={(v) => commitField(row, "costCenterId", v)}
                        onCancel={() => setEditing(null)}
                      />
                    ) : (
                      <CellButton
                        onClick={() =>
                          setEditing({ rowId: row.id, field: "costCenterId" })
                        }
                      >
                        {row.costCenterName ?? "—"}
                      </CellButton>
                    )}
                  </TableCell>
                  <TableCell
                    className={`text-right tabular-nums ${
                      row.type === "receita"
                        ? "text-emerald-600"
                        : "text-rose-600"
                    } ${isParentRow ? "font-semibold" : ""}`}
                  >
                    {isParentRow ? (
                      <span>
                        {row.type === "receita" ? "+" : "−"}
                        {formatCurrency(displayAmount)}
                      </span>
                    ) : isEditing(row, "amount") ? (
                      <InlineInput
                        type="decimal"
                        initial={row.amount.toFixed(2).replace(".", ",")}
                        pending={pending}
                        className="text-right"
                        onCommit={(v) => commitField(row, "amount", v)}
                        onCancel={() => setEditing(null)}
                      />
                    ) : (
                      <CellButton
                        onClick={() =>
                          setEditing({ rowId: row.id, field: "amount" })
                        }
                        className="w-full text-right"
                      >
                        {row.type === "receita" ? "+" : "−"}
                        {formatCurrency(row.amount)}
                      </CellButton>
                    )}
                  </TableCell>
                  <TableCell className="text-center">
                    {row.virtual ? (
                      <Switch checked={row.paid} disabled />
                    ) : (
                      <Switch
                        checked={row.paid}
                        onCheckedChange={(v) => togglePaid(row, v)}
                        disabled={pending}
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    {row.virtual ? null : (
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
                          {row.recurrenceId ? (
                            <>
                              <DropdownMenuItem
                                onClick={() => setEditingRecurrent(row)}
                              >
                                <Pencil className="h-4 w-4" />
                                Editar recorrência
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => setUnlinking(row)}
                              >
                                <Link2Off className="h-4 w-4" />
                                Desvincular recorrência
                              </DropdownMenuItem>
                            </>
                          ) : isParentRow ? (
                            <>
                              <DropdownMenuItem
                                onClick={() => setImportingTo(row)}
                              >
                                <ClipboardPaste className="h-4 w-4" />
                                Importar itens (CSV)
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => setUnmaking(row)}
                              >
                                <Layers className="h-4 w-4" />
                                Desfazer agrupador
                              </DropdownMenuItem>
                            </>
                          ) : row.parentId ? (
                            <DropdownMenuItem
                              onClick={() => handleDetachFromParent(row)}
                            >
                              <Unlink className="h-4 w-4" />
                              Desvincular do pai
                            </DropdownMenuItem>
                          ) : (
                            <>
                              <DropdownMenuItem onClick={() => setConverting(row)}>
                                <Repeat className="h-4 w-4" />
                                Tornar recorrente
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => handleMakeParent(row)}
                              >
                                <Layers className="h-4 w-4" />
                                Tornar agrupador
                              </DropdownMenuItem>
                            </>
                          )}
                          <DropdownMenuItem
                            variant="destructive"
                            onClick={() => setDeleting(row)}
                          >
                            <Trash2 className="h-4 w-4" />
                            Excluir
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>

      <VirtualRowDetailsDialog
        row={detailRow}
        onClose={() => setDetailRow(null)}
      />

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

      <ImportFaturaDialog
        row={importingTo}
        categories={categories}
        costCenters={costCenters}
        onClose={() => setImportingTo(null)}
      />

      <Dialog
        open={unmaking !== null}
        onOpenChange={(open) => !open && setUnmaking(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Desfazer agrupador?</DialogTitle>
            <DialogDescription>
              {unmaking
                ? `"${unmaking.description}" deixará de ser agrupador. O que fazer com os itens?`
                : null}
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            <Button
              variant="default"
              onClick={() => unmaking && handleUnmakeParent(unmaking, "detach")}
              disabled={pending}
            >
              Desvincular itens (viram avulsos)
            </Button>
            <Button
              variant="destructive"
              onClick={() => unmaking && handleUnmakeParent(unmaking, "delete")}
              disabled={pending}
            >
              Excluir itens junto
            </Button>
            <Button
              variant="ghost"
              onClick={() => setUnmaking(null)}
              disabled={pending}
            >
              Cancelar
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <ConvertToRecurrentDialog
        row={converting}
        pending={pending}
        onClose={() => setConverting(null)}
        onConfirm={(parcels, day) =>
          converting && handleConvert(converting, parcels, day)
        }
      />

      <EditRecurrentTransactionDialog
        row={editingRecurrent}
        categories={categories}
        costCenters={costCenters}
        pending={pending}
        onClose={() => setEditingRecurrent(null)}
        onConfirm={(scope, patch) =>
          editingRecurrent && handleEditRecurrent(editingRecurrent, scope, patch)
        }
      />

      <Dialog
        open={scopePrompt !== null}
        onOpenChange={(open) => {
          if (!open) {
            setScopePrompt(null);
            setEditing(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Aplicar em quais parcelas?</DialogTitle>
            <DialogDescription>
              {scopePrompt ? (
                <>
                  A transação{" "}
                  <strong>&ldquo;{scopePrompt.row.description}&rdquo;</strong>{" "}
                  faz parte de uma recorrência. Onde você quer aplicar essa
                  alteração?
                </>
              ) : null}
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col sm:flex-row gap-2 pt-2">
            <Button
              type="button"
              variant="outline"
              className="flex-1"
              onClick={() => handleScopePromptChoose("single")}
              disabled={pending}
            >
              Apenas esta
            </Button>
            <Button
              type="button"
              variant="outline"
              className="flex-1"
              onClick={() => handleScopePromptChoose("futures")}
              disabled={pending}
            >
              Esta e as próximas
            </Button>
            <Button
              type="button"
              className="flex-1"
              onClick={() => handleScopePromptChoose("all")}
              disabled={pending}
            >
              Todas
            </Button>
          </div>
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              setScopePrompt(null);
              setEditing(null);
            }}
            disabled={pending}
          >
            Cancelar
          </Button>
        </DialogContent>
      </Dialog>

      <Dialog
        open={unlinking !== null}
        onOpenChange={(open) => !open && setUnlinking(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Desvincular recorrência?</DialogTitle>
            <DialogDescription>
              {unlinking ? (
                <>
                  Todas as parcelas de{" "}
                  <strong>&ldquo;{unlinking.description}&rdquo;</strong>{" "}
                  continuam como transações avulsas, mas perdem o vínculo com a
                  recorrência (o indicador <code>parcela X/Y</code> some). O
                  registro da recorrência é apagado. Ação irreversível.
                </>
              ) : null}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => setUnlinking(null)}
              disabled={pending}
            >
              Cancelar
            </Button>
            <Button
              variant="destructive"
              onClick={() => unlinking && handleUnlink(unlinking)}
              disabled={pending}
            >
              Desvincular
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function ConvertToRecurrentDialog({
  row,
  pending,
  onClose,
  onConfirm,
}: {
  row: Row | null;
  pending: boolean;
  onClose: () => void;
  onConfirm: (
    totalParcelsOrForever: number | "forever",
    dayOfMonth: number,
  ) => void;
}) {
  const defaultDay = row ? Number(row.date.slice(8, 10)) : 1;
  const [forever, setForever] = useState(false);
  return (
    <Dialog
      open={row !== null}
      onOpenChange={(open) => {
        if (!open) {
          setForever(false);
          onClose();
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Tornar recorrente</DialogTitle>
          <DialogDescription>
            {row
              ? `"${row.description}" vira a 1ª parcela. As demais são criadas não pagas.`
              : null}
          </DialogDescription>
        </DialogHeader>
        {row ? (
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              const day = Number.parseInt(String(fd.get("dayOfMonth") ?? ""), 10);
              if (forever) {
                onConfirm("forever", day);
              } else {
                const parcels = Number.parseInt(
                  String(fd.get("totalParcels") ?? ""),
                  10,
                );
                onConfirm(parcels, day);
              }
            }}
          >
            <div className="flex items-center gap-3">
              <Switch
                checked={forever}
                onCheckedChange={setForever}
                id="convert-forever"
              />
              <label htmlFor="convert-forever" className="text-sm cursor-pointer">
                Pra sempre
              </label>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {forever ? null : (
                <div className="flex flex-col gap-2">
                  <label htmlFor="totalParcels" className="text-sm font-medium">
                    Parcelas
                  </label>
                  <Input
                    id="totalParcels"
                    name="totalParcels"
                    type="number"
                    min="2"
                    max="240"
                    defaultValue="12"
                    required
                  />
                </div>
              )}
              <div className={`flex flex-col gap-2 ${forever ? "col-span-2" : ""}`}>
                <label htmlFor="dayOfMonth" className="text-sm font-medium">
                  Dia do mês (1-31)
                </label>
                <Input
                  id="dayOfMonth"
                  name="dayOfMonth"
                  type="number"
                  min="1"
                  max="31"
                  defaultValue={String(defaultDay)}
                  required
                />
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={onClose} disabled={pending}>
                Cancelar
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? "Criando..." : "Criar recorrência"}
              </Button>
            </DialogFooter>
          </form>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function EditRecurrentTransactionDialog({
  row,
  categories,
  costCenters,
  pending,
  onClose,
  onConfirm,
}: {
  row: Row | null;
  categories: Category[];
  costCenters: CostCenter[];
  pending: boolean;
  onClose: () => void;
  onConfirm: (scope: RecurrentEditScope, patch: RecurrentEditPatch) => void;
}) {
  return (
    <Dialog
      open={row !== null}
      onOpenChange={(v) => {
        if (!v) onClose();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Editar transação recorrente</DialogTitle>
          <DialogDescription>
            Escolha o escopo da mudança ao salvar. Parcelas já pagas nunca são
            alteradas nos escopos plurais.
          </DialogDescription>
        </DialogHeader>
        {row ? (
          <EditRecurrentForm
            key={row.id}
            row={row}
            categories={categories}
            costCenters={costCenters}
            pending={pending}
            onClose={onClose}
            onConfirm={onConfirm}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function EditRecurrentForm({
  row,
  categories,
  costCenters,
  pending,
  onClose,
  onConfirm,
}: {
  row: Row;
  categories: Category[];
  costCenters: CostCenter[];
  pending: boolean;
  onClose: () => void;
  onConfirm: (scope: RecurrentEditScope, patch: RecurrentEditPatch) => void;
}) {
  const isDespesa = row.type === "despesa";
  const initialDescription = row.description;
  const initialAmount = row.amount;
  const initialCategoryId = row.categoryId;
  const initialCostCenterId = row.costCenterId;
  const initialDayOfMonth = row.dayOfMonth ?? Number(row.date.slice(8, 10));

  const [description, setDescription] = useState(initialDescription);
  const [amount, setAmount] = useState(String(initialAmount));
  const [categoryId, setCategoryId] = useState<string>(
    initialCategoryId ?? NO_CATEGORY,
  );
  const [costCenterId, setCostCenterId] = useState<string>(
    initialCostCenterId ?? NO_CATEGORY,
  );
  const [dayOfMonth, setDayOfMonth] = useState(String(initialDayOfMonth));
  const [extraCategories, setExtraCategories] = useState<Category[]>([]);
  const [extraCostCenters, setExtraCostCenters] = useState<CostCenter[]>([]);

  function submit(scope: RecurrentEditScope) {
    const patch: RecurrentEditPatch = {};

    const trimmed = description.trim();
    if (trimmed !== initialDescription) patch.description = trimmed;

    const numAmount = Number.parseFloat(amount);
    if (Number.isFinite(numAmount) && numAmount !== initialAmount)
      patch.amount = numAmount;

    const nextCat = categoryId === NO_CATEGORY ? null : categoryId;
    if (nextCat !== initialCategoryId) patch.categoryId = nextCat;

    if (isDespesa) {
      const nextCc = costCenterId === NO_CATEGORY ? null : costCenterId;
      if (nextCc !== initialCostCenterId) patch.costCenterId = nextCc;
    }

    if (scope !== "single") {
      const nextDay = Number.parseInt(dayOfMonth, 10);
      if (Number.isFinite(nextDay) && nextDay !== initialDayOfMonth)
        patch.dayOfMonth = nextDay;
    }

    if (Object.keys(patch).length === 0) {
      toast.info("Nada mudou.");
      return;
    }
    onConfirm(scope, patch);
  }

  const mergedCategories = [
    ...categories,
    ...extraCategories.filter((c) => !categories.some((x) => x.id === c.id)),
  ];
  const mergedCostCenters = [
    ...costCenters,
    ...extraCostCenters.filter((c) => !costCenters.some((x) => x.id === c.id)),
  ];
  const categoryOptions = mergedCategories.filter((c) => c.type === row.type);

  return (
    <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="edit-description">Descrição</Label>
              <Input
                id="edit-description"
                value={description}
                onChange={(e) => setDescription(e.currentTarget.value)}
                disabled={pending}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-2">
                <Label htmlFor="edit-amount">Valor (R$)</Label>
                <Input
                  id="edit-amount"
                  type="number"
                  step="0.01"
                  min="0"
                  value={amount}
                  onChange={(e) => setAmount(e.currentTarget.value)}
                  disabled={pending}
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="edit-dayOfMonth">Dia do mês (1-31)</Label>
                <Input
                  id="edit-dayOfMonth"
                  type="number"
                  min="1"
                  max="31"
                  value={dayOfMonth}
                  onChange={(e) => setDayOfMonth(e.currentTarget.value)}
                  disabled={pending}
                />
                <p className="text-xs text-muted-foreground">
                  Só se aplica aos escopos plurais.
                </p>
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="edit-categoryId">Categoria</Label>
              <Combobox
                id="edit-categoryId"
                value={categoryId === NO_CATEGORY ? null : categoryId}
                onChange={(v) => setCategoryId(v ?? NO_CATEGORY)}
                options={categoryOptions}
                noneLabel="Sem categoria"
                placeholder="Sem categoria"
                disabled={pending}
                onCreate={async (name) => {
                  const created = await createCategoryInline(name, row.type);
                  setExtraCategories((prev) => [
                    ...prev,
                    {
                      id: created.id,
                      name: created.name,
                      type: created.type,
                      createdAt: Date.now(),
                    },
                  ]);
                  return { id: created.id, name: created.name };
                }}
                onCreateError={(err) =>
                  toast.error(
                    err instanceof Error
                      ? err.message
                      : "Não foi possível criar a categoria.",
                  )
                }
              />
            </div>
            {isDespesa ? (
              <div className="flex flex-col gap-2">
                <Label htmlFor="edit-costCenterId">Centro de custo</Label>
                <Combobox
                  id="edit-costCenterId"
                  value={costCenterId === NO_CATEGORY ? null : costCenterId}
                  onChange={(v) => setCostCenterId(v ?? NO_CATEGORY)}
                  options={mergedCostCenters}
                  noneLabel="Sem centro de custo"
                  placeholder="Sem centro de custo"
                  disabled={pending}
                  onCreate={async (name) => {
                    const created = await createCostCenterInline(name);
                    setExtraCostCenters((prev) => [
                      ...prev,
                      {
                        id: created.id,
                        name: created.name,
                        createdAt: Date.now(),
                      },
                    ]);
                    return created;
                  }}
                  onCreateError={(err) =>
                    toast.error(
                      err instanceof Error
                        ? err.message
                        : "Não foi possível criar o centro de custo.",
                    )
                  }
                />
              </div>
            ) : null}
            <div className="flex flex-col gap-2 pt-2">
              <div className="text-xs text-muted-foreground">
                Aplicar alterações em:
              </div>
              <div className="flex flex-col sm:flex-row gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => submit("single")}
                  disabled={pending}
                >
                  Apenas esta
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => submit("futures")}
                  disabled={pending}
                >
                  Esta e as próximas
                </Button>
                <Button
                  type="button"
                  className="flex-1"
                  onClick={() => submit("all")}
                  disabled={pending}
                >
                  Todas
                </Button>
              </div>
              <Button
                type="button"
                variant="ghost"
                onClick={onClose}
                disabled={pending}
              >
                Cancelar
              </Button>
      </div>
    </div>
  );
}

function CellButton({
  onClick,
  children,
  className,
}: {
  onClick: () => void;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-left rounded px-1 -mx-1 hover:bg-muted/60 transition-colors ${className ?? ""}`}
    >
      {children}
    </button>
  );
}

function buildClaudePrompt(
  parentType: "receita" | "despesa",
  parentDate: string,
  categories: Category[],
  costCenters: CostCenter[],
): string {
  const cats = categories
    .filter((c) => c.type === parentType)
    .map((c) => `- ${c.name}`)
    .join("\n");
  const ccs = costCenters.map((c) => `- ${c.name}`).join("\n");
  const ccBlock =
    parentType === "despesa"
      ? `

Centros de custo válidos:
${ccs || "(nenhum cadastrado)"}`
      : "";

  return `Vou colar uma fatura/extrato. Extraia cada transação e devolva em CSV (separado por vírgulas), nesta ordem de colunas:

data,descrição,valor,categoria,centro_de_custo

Regras:
- Uma transação por linha. Sem cabeçalho.
- data: YYYY-MM-DD. Se faltar o ano, use ${parentDate.slice(0, 4)}. Se não houver data, use ${parentDate}.
- valor: positivo, formato brasileiro (ex: 1234,56). Sem R$.
- descrição: limpa, sem códigos de autorização. Se houver vírgula na descrição, envolva em aspas duplas.
- categoria: escolha exatamente UMA da lista abaixo (cole o nome igual). Se nada encaixar, deixe vazio. Nunca invente.${parentType === "despesa" ? "\n- centro_de_custo: idem, da lista abaixo. Vazio se incerto." : "\n- centro_de_custo: deixe vazio (esta é uma receita)."}
- Ignore: cabeçalhos da fatura, totais, juros agregados, mensagens de marketing, datas de vencimento.
- Devolva só o CSV cru, sem explicação, sem código-cerca.

Categorias válidas (${parentType}):
${cats || "(nenhuma cadastrada)"}${ccBlock}

Fatura:
[cole aqui]`;
}

function ImportFaturaDialog({
  row,
  categories,
  costCenters,
  onClose,
}: {
  row: Row | null;
  categories: Category[];
  costCenters: CostCenter[];
  onClose: () => void;
}) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

  const prompt = row
    ? buildClaudePrompt(row.type, row.date, categories, costCenters)
    : "";

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(prompt);
      toast.success("Prompt copiado. Cole no Claude.ai junto com a fatura.");
    } catch {
      toast.error("Falha ao copiar.");
    }
  }

  async function submit() {
    if (!row) return;
    if (!text.trim()) {
      toast.error("Cole o CSV gerado pelo Claude.");
      return;
    }
    setBusy(true);
    try {
      const result = await importChildrenFromText(row.id, text);
      if (result.created === 0) {
        toast.warning("Nenhum item encontrado no texto.");
      } else {
        const parts = [`${result.created} itens criados`];
        if (result.skipped > 0) parts.push(`${result.skipped} ignorados`);
        if (result.unmatchedCategories > 0)
          parts.push(`${result.unmatchedCategories} sem categoria`);
        if (result.unmatchedCostCenters > 0)
          parts.push(`${result.unmatchedCostCenters} sem CC`);
        toast.success(parts.join(", ") + ".");
      }
      setText("");
      onClose();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Falha ao importar.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={row !== null}
      onOpenChange={(open) => !open && !busy && onClose()}
    >
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Importar itens da fatura</DialogTitle>
          <DialogDescription>
            Cole o CSV com os itens. Os filhos serão criados em{" "}
            <strong>{row?.description}</strong>. Categorias e centros de custo
            são casados por nome (acentos e maiúsculas ignorados).
          </DialogDescription>
        </DialogHeader>
        <details className="text-sm">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground select-none">
            Não tem CSV? Use o Claude.ai pra converter →
          </summary>
          <div className="mt-2 space-y-2">
            <p className="text-xs text-muted-foreground">
              Copie o prompt abaixo, cole no Claude.ai junto com a fatura,
              copie o CSV de volta e cole aqui.
            </p>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={copyPrompt}
            >
              Copiar prompt
            </Button>
            <pre className="text-xs bg-muted/40 rounded-md p-3 max-h-40 overflow-auto whitespace-pre-wrap">
              {prompt}
            </pre>
          </div>
        </details>
        <textarea
          value={text}
          onChange={(e) => setText(e.currentTarget.value)}
          disabled={busy}
          placeholder={`Exemplo:\n2026-05-10,Mercado XPTO,123,45,Alimentação,Casa\n2026-05-11,Uber,45,67,Transporte,Casa`}
          rows={12}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono resize-y outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
        />
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancelar
          </Button>
          <Button onClick={submit} disabled={busy || !text.trim()}>
            {busy ? "Importando..." : "Importar"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AddChildRow({
  parentId,
  parentType,
  parentDate,
  categories,
  costCenters,
  isOpen,
  onOpen,
  onClose,
}: {
  parentId: string;
  parentType: "receita" | "despesa";
  parentDate: string;
  categories: Category[];
  costCenters: CostCenter[];
  isOpen: boolean;
  onOpen: () => void;
  onClose: () => void;
}) {
  const [description, setDescription] = useState("");
  const [amount, setAmount] = useState("");
  const [categoryId, setCategoryId] = useState<string | null>(null);
  const [costCenterId, setCostCenterId] = useState<string | null>(null);
  const [extraCategories, setExtraCategories] = useState<Category[]>([]);
  const [extraCostCenters, setExtraCostCenters] = useState<CostCenter[]>([]);
  const [busy, setBusy] = useState(false);

  function reset() {
    setDescription("");
    setAmount("");
    setCategoryId(null);
    setCostCenterId(null);
  }

  const allCats = useMemo(
    () =>
      [...categories, ...extraCategories]
        .filter((c) => c.type === parentType)
        .map((c) => ({ id: c.id, name: c.name })),
    [categories, extraCategories, parentType],
  );
  const allCcs = useMemo(
    () => [...costCenters, ...extraCostCenters].map((c) => ({ id: c.id, name: c.name })),
    [costCenters, extraCostCenters],
  );

  async function submit() {
    if (!description.trim() || !amount.trim()) {
      toast.error("Descrição e valor obrigatórios.");
      return;
    }
    setBusy(true);
    const fd = new FormData();
    fd.set("description", description.trim());
    fd.set("amount", amount.trim());
    fd.set("date", parentDate);
    if (categoryId) fd.set("categoryId", categoryId);
    if (costCenterId && parentType === "despesa")
      fd.set("costCenterId", costCenterId);
    try {
      const res = await addChild(parentId, fd);
      if (res?.error) {
        toast.error(res.error);
      } else {
        toast.success("Item adicionado.");
        reset();
      }
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Não foi possível adicionar.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!isOpen) {
    return (
      <TableRow className="bg-rose-50/40 hover:bg-rose-50/60">
        <TableCell colSpan={7} className="py-2">
          <button
            type="button"
            onClick={onOpen}
            className="flex items-center gap-2 text-sm text-rose-700 hover:text-rose-800 px-2 py-1 rounded hover:bg-rose-100/50 transition cursor-pointer pl-8"
          >
            <Plus className="h-4 w-4" />
            Adicionar item
          </button>
        </TableCell>
      </TableRow>
    );
  }

  return (
    <TableRow className="bg-rose-50/40">
      <TableCell className="text-xs text-muted-foreground tabular-nums">
        {formatDateBR(parentDate)}
      </TableCell>
      <TableCell>
        <Input
          autoFocus
          value={description}
          onChange={(e) => setDescription(e.currentTarget.value)}
          placeholder="Descrição"
          disabled={busy}
        />
      </TableCell>
      <TableCell>
        <Combobox
          value={categoryId}
          onChange={setCategoryId}
          options={allCats}
          placeholder="Categoria"
          disabled={busy}
          onCreate={async (name) => {
            const created = await createCategoryInline(name, parentType);
            const cat: Category = {
              id: created.id,
              name: created.name,
              type: parentType,
              createdAt: Date.now(),
            };
            setExtraCategories((prev) => [...prev, cat]);
            return { id: created.id, name: created.name };
          }}
          onCreateError={(err) =>
            toast.error(
              err instanceof Error ? err.message : "Não foi possível criar.",
            )
          }
        />
      </TableCell>
      <TableCell>
        {parentType === "despesa" ? (
          <Combobox
            value={costCenterId}
            onChange={setCostCenterId}
            options={allCcs}
            placeholder="Centro"
            disabled={busy}
            onCreate={async (name) => {
              const created = await createCostCenterInline(name);
              const cc: CostCenter = {
                id: created.id,
                name: created.name,
                createdAt: Date.now(),
              };
              setExtraCostCenters((prev) => [...prev, cc]);
              return { id: created.id, name: created.name };
            }}
            onCreateError={(err) =>
              toast.error(
                err instanceof Error ? err.message : "Não foi possível criar.",
              )
            }
          />
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
      <TableCell>
        <Input
          type="text"
          inputMode="decimal"
          value={amount}
          onChange={(e) => setAmount(e.currentTarget.value)}
          placeholder="0,00"
          className="text-right"
          disabled={busy}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              submit();
            } else if (e.key === "Escape") {
              e.preventDefault();
              onClose();
            }
          }}
        />
      </TableCell>
      <TableCell />
      <TableCell>
        <div className="flex gap-1">
          <Button
            type="button"
            size="sm"
            onClick={submit}
            disabled={busy}
          >
            Salvar
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => {
              reset();
              onClose();
            }}
            disabled={busy}
          >
            ✕
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

function InlineInput({
  type,
  initial,
  pending,
  className,
  step,
  min,
  onCommit,
  onCancel,
}: {
  type: "text" | "date" | "number" | "decimal";
  initial: string;
  pending: boolean;
  className?: string;
  step?: string;
  min?: string;
  onCommit: (v: string) => void;
  onCancel: () => void;
}) {
  const [cancelled, setCancelled] = useState(false);
  const isDecimal = type === "decimal";
  return (
    <Input
      type={isDecimal ? "text" : type}
      inputMode={isDecimal ? "decimal" : undefined}
      pattern={isDecimal ? "[0-9]+([.,][0-9]{1,2})?" : undefined}
      defaultValue={initial}
      autoFocus
      step={isDecimal ? undefined : step}
      min={isDecimal ? undefined : min}
      disabled={pending}
      className={className}
      onFocus={(e) => {
        if (type === "text" || type === "number" || isDecimal)
          e.currentTarget.select();
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          e.currentTarget.blur();
        } else if (e.key === "Escape") {
          e.preventDefault();
          setCancelled(true);
          e.currentTarget.blur();
        }
      }}
      onBlur={(e) => {
        if (cancelled) {
          onCancel();
          return;
        }
        const v = e.currentTarget.value;
        if (v === initial || v === "") onCancel();
        else onCommit(v);
      }}
    />
  );
}

type ComboOption =
  | { kind: "none" }
  | { kind: "existing"; id: string; label: string }
  | { kind: "create"; name: string };

function InlineCategorySelect({
  rowType,
  categories,
  pending,
  onCommit,
  onCancel,
}: {
  rowType: "receita" | "despesa";
  categories: Category[];
  pending: boolean;
  onCommit: (v: string) => void;
  onCancel: () => void;
}) {
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const [busy, setBusy] = useState(false);

  const q = query.trim().toLowerCase();
  const filtered = q
    ? categories.filter((c) => c.name.toLowerCase().includes(q))
    : categories;
  const exactMatch = categories.some(
    (c) => c.name.trim().toLowerCase() === q,
  );

  const options: ComboOption[] = [];
  if (!q) options.push({ kind: "none" });
  for (const c of filtered) options.push({ kind: "existing", id: c.id, label: c.name });
  if (q && !exactMatch)
    options.push({ kind: "create", name: query.trim() });

  const safeIdx = Math.min(activeIdx, Math.max(options.length - 1, 0));

  async function pick(opt: ComboOption) {
    if (opt.kind === "none") {
      onCommit(NO_CATEGORY);
    } else if (opt.kind === "existing") {
      onCommit(opt.id);
    } else {
      setBusy(true);
      try {
        const created = await createCategoryInline(opt.name, rowType);
        onCommit(created.id);
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : "Não foi possível criar a categoria.",
        );
        setBusy(false);
      }
    }
  }

  return (
    <div className="relative">
      <Input
        type="text"
        autoFocus
        value={query}
        disabled={pending || busy}
        placeholder="Buscar ou criar..."
        onChange={(e) => {
          setQuery(e.currentTarget.value);
          setActiveIdx(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActiveIdx((i) => Math.min(i + 1, options.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActiveIdx((i) => Math.max(i - 1, 0));
          } else if (e.key === "Enter") {
            e.preventDefault();
            const opt = options[safeIdx];
            if (opt) pick(opt);
          } else if (e.key === "Escape") {
            e.preventDefault();
            onCancel();
          }
        }}
        onBlur={() => {
          if (!busy) onCancel();
        }}
      />
      {options.length > 0 ? (
        <div className="absolute top-full left-0 z-20 mt-1 flex w-56 max-h-60 flex-col overflow-y-auto rounded-lg bg-popover text-popover-foreground shadow-md ring-1 ring-foreground/10">
          {options.map((opt, i) => {
            const isActive = i === safeIdx;
            const label =
              opt.kind === "none"
                ? "Sem categoria"
                : opt.kind === "existing"
                  ? opt.label
                  : `Criar "${opt.name}"`;
            return (
              <button
                key={opt.kind === "existing" ? opt.id : opt.kind + i}
                type="button"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(opt)}
                className={`w-full text-left px-2.5 py-1.5 text-sm ${
                  isActive ? "bg-accent text-accent-foreground" : ""
                } ${opt.kind === "create" ? "text-muted-foreground italic" : ""}`}
              >
                {label}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function InlineCostCenterSelect({
  costCenters,
  pending,
  onCommit,
  onCancel,
}: {
  costCenters: CostCenter[];
  pending: boolean;
  onCommit: (v: string) => void;
  onCancel: () => void;
}) {
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const [busy, setBusy] = useState(false);

  const q = query.trim().toLowerCase();
  const filtered = q
    ? costCenters.filter((c) => c.name.toLowerCase().includes(q))
    : costCenters;
  const exactMatch = costCenters.some(
    (c) => c.name.trim().toLowerCase() === q,
  );

  const options: ComboOption[] = [];
  if (!q) options.push({ kind: "none" });
  for (const c of filtered) options.push({ kind: "existing", id: c.id, label: c.name });
  if (q && !exactMatch)
    options.push({ kind: "create", name: query.trim() });

  const safeIdx = Math.min(activeIdx, Math.max(options.length - 1, 0));

  async function pick(opt: ComboOption) {
    if (opt.kind === "none") {
      onCommit(NO_CATEGORY);
    } else if (opt.kind === "existing") {
      onCommit(opt.id);
    } else {
      setBusy(true);
      try {
        const created = await createCostCenterInline(opt.name);
        onCommit(created.id);
      } catch (err) {
        toast.error(
          err instanceof Error
            ? err.message
            : "Não foi possível criar o centro de custo.",
        );
        setBusy(false);
      }
    }
  }

  return (
    <div className="relative">
      <Input
        type="text"
        autoFocus
        value={query}
        disabled={pending || busy}
        placeholder="Buscar ou criar..."
        onChange={(e) => {
          setQuery(e.currentTarget.value);
          setActiveIdx(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActiveIdx((i) => Math.min(i + 1, options.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActiveIdx((i) => Math.max(i - 1, 0));
          } else if (e.key === "Enter") {
            e.preventDefault();
            const opt = options[safeIdx];
            if (opt) pick(opt);
          } else if (e.key === "Escape") {
            e.preventDefault();
            onCancel();
          }
        }}
        onBlur={() => {
          if (!busy) onCancel();
        }}
      />
      {options.length > 0 ? (
        <div className="absolute top-full left-0 z-20 mt-1 flex w-56 max-h-60 flex-col overflow-y-auto rounded-lg bg-popover text-popover-foreground shadow-md ring-1 ring-foreground/10">
          {options.map((opt, i) => {
            const isActive = i === safeIdx;
            const label =
              opt.kind === "none"
                ? "Sem centro de custo"
                : opt.kind === "existing"
                  ? opt.label
                  : `Criar "${opt.name}"`;
            return (
              <button
                key={opt.kind === "existing" ? opt.id : opt.kind + i}
                type="button"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(opt)}
                className={`w-full text-left px-2.5 py-1.5 text-sm ${
                  isActive ? "bg-accent text-accent-foreground" : ""
                } ${opt.kind === "create" ? "text-muted-foreground italic" : ""}`}
              >
                {label}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function SortableHead({
  label,
  sortKey,
  activeKey,
  activeDir,
  onToggle,
  className,
  align,
}: {
  label: string;
  sortKey: SortKey;
  activeKey: SortKey;
  activeDir: SortDir;
  onToggle: (k: SortKey) => void;
  className?: string;
  align?: "start" | "center" | "end";
}) {
  const isActive = activeKey === sortKey;
  const Icon = !isActive
    ? ArrowUpDown
    : activeDir === "asc"
      ? ArrowUp
      : ArrowDown;
  const justify =
    align === "end"
      ? "justify-end"
      : align === "center"
        ? "justify-center"
        : "justify-start";
  return (
    <TableHead className={className}>
      <button
        type="button"
        onClick={() => onToggle(sortKey)}
        className={`flex w-full items-center gap-1.5 ${justify} ${isActive ? "text-foreground" : "text-muted-foreground"} hover:text-foreground transition-colors`}
      >
        <span>{label}</span>
        <Icon className="h-3.5 w-3.5 opacity-60" />
      </button>
    </TableHead>
  );
}
