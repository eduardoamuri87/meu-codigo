"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { Pencil, Plus, Trash2 } from "lucide-react";
import type { CostCenter } from "@/lib/db/schema";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
  createCostCenter,
  deleteCostCenter,
  updateCostCenter,
} from "./actions";

type Editing = { mode: "new" } | { mode: "edit"; costCenter: CostCenter } | null;

export function CostCentersClient({
  costCenters,
}: {
  costCenters: CostCenter[];
}) {
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<CostCenter | null>(null);
  const [pending, startTransition] = useTransition();

  function handleDelete(cc: CostCenter) {
    startTransition(async () => {
      const result = await deleteCostCenter(cc.id);
      if (result.ok) {
        toast.success("Centro de custo excluído.");
        setDeleting(null);
      } else {
        toast.error(result.error);
      }
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-semibold tracking-tight">
          Centros de custo
        </h1>
        <Button onClick={() => setEditing({ mode: "new" })}>
          <Plus className="h-4 w-4" />
          Novo centro de custo
        </Button>
      </div>

      {costCenters.length === 0 ? (
        <div className="card-soft p-12 text-center text-muted-foreground">
          Nenhum centro de custo criado ainda.
        </div>
      ) : (
        <div className="card-soft overflow-x-auto [&_th]:h-12 [&_th]:px-5 [&_td]:py-4 [&_td]:px-5">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nome</TableHead>
                <TableHead className="w-28 text-right">Ações</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {costCenters.map((cc) => (
                <TableRow key={cc.id}>
                  <TableCell>{cc.name}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() =>
                          setEditing({ mode: "edit", costCenter: cc })
                        }
                        aria-label="Editar"
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => setDeleting(cc)}
                        aria-label="Excluir"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <CostCenterDialog editing={editing} onClose={() => setEditing(null)} />

      <Dialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Excluir centro de custo?</DialogTitle>
            <DialogDescription>
              {deleting
                ? `Tem certeza que quer excluir "${deleting.name}"? Esta ação não pode ser desfeita.`
                : null}
            </DialogDescription>
          </DialogHeader>
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
              onClick={() => deleting && handleDelete(deleting)}
              disabled={pending}
            >
              Excluir
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CostCenterDialog({
  editing,
  onClose,
}: {
  editing: Editing;
  onClose: () => void;
}) {
  const [pending, startTransition] = useTransition();

  const open = editing !== null;
  const isEdit = editing?.mode === "edit";
  const current = isEdit ? editing.costCenter : null;

  function onSubmit(formData: FormData) {
    startTransition(async () => {
      const result = isEdit
        ? await updateCostCenter(formData)
        : await createCostCenter(formData);
      if (result.ok) {
        toast.success(
          isEdit ? "Centro de custo atualizado." : "Centro de custo criado.",
        );
        onClose();
      } else {
        toast.error(result.error);
      }
    });
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {isEdit ? "Editar centro de custo" : "Novo centro de custo"}
          </DialogTitle>
        </DialogHeader>
        <form
          action={onSubmit}
          className="flex flex-col gap-4"
          key={current?.id ?? "new"}
        >
          {current ? (
            <input type="hidden" name="id" value={current.id} />
          ) : null}
          <div className="flex flex-col gap-2">
            <Label htmlFor="name">Nome</Label>
            <Input
              id="name"
              name="name"
              defaultValue={current?.name ?? ""}
              required
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={onClose}
              disabled={pending}
            >
              Cancelar
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? "Salvando..." : "Salvar"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
