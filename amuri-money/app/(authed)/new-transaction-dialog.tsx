"use client";

import { useState } from "react";
import { Plus } from "lucide-react";
import type { Category, CostCenter } from "@/lib/db/schema";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { TransactionForm } from "./transacoes/transaction-form";

export function NewTransactionDialog({
  categories,
  costCenters,
}: {
  categories: Category[];
  costCenters: CostCenter[];
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button type="button" onClick={() => setOpen(true)} className="sm:ml-auto">
        <Plus className="h-4 w-4" />
        Nova transação
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Nova transação</DialogTitle>
          </DialogHeader>
          {open ? (
            <TransactionForm
              categories={categories}
              costCenters={costCenters}
              onSuccess={() => setOpen(false)}
              onCancel={() => setOpen(false)}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
