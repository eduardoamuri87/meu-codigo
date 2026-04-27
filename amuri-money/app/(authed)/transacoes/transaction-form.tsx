"use client";

import { useActionState, useEffect, useState } from "react";
import { useFormStatus } from "react-dom";
import Link from "next/link";
import type { Category, CostCenter, Transaction } from "@/lib/db/schema";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  createTransaction,
  updateTransaction,
  type FormState,
} from "./actions";

const NO_CATEGORY = "__none__";

function SubmitButton({ isEdit }: { isEdit: boolean }) {
  const { pending } = useFormStatus();
  return (
    <Button
      type="submit"
      disabled={pending}
      className="h-11 px-5 text-base"
    >
      {pending ? "Salvando..." : isEdit ? "Salvar alterações" : "Criar"}
    </Button>
  );
}

export type TransactionFormValues = Pick<
  Transaction,
  | "id"
  | "type"
  | "paid"
  | "date"
  | "amount"
  | "description"
  | "categoryId"
  | "costCenterId"
  | "recurrenceId"
  | "parcelNumber"
>;

export function TransactionForm({
  categories,
  costCenters,
  transaction,
  onSuccess,
  onCancel,
}: {
  categories: Category[];
  costCenters: CostCenter[];
  transaction?: TransactionFormValues;
  onSuccess?: () => void;
  onCancel?: () => void;
}) {
  const isEdit = Boolean(transaction);
  const action = isEdit ? updateTransaction : createTransaction;
  const [state, formAction] = useActionState<FormState, FormData>(
    action,
    undefined,
  );

  useEffect(() => {
    if (state?.ok) onSuccess?.();
  }, [state, onSuccess]);

  const [type, setType] = useState<"receita" | "despesa">(
    transaction?.type ?? "despesa",
  );
  const [paid, setPaid] = useState<boolean>(transaction?.paid ?? false);
  const [isRecurrent, setIsRecurrent] = useState(false);
  const [foreverRecurrence, setForeverRecurrence] = useState(false);
  const [categoryId, setCategoryId] = useState<string>(
    transaction?.categoryId ?? NO_CATEGORY,
  );
  const [costCenterId, setCostCenterId] = useState<string>(
    transaction?.costCenterId ?? NO_CATEGORY,
  );
  const today = new Date().toISOString().slice(0, 10);
  const defaultDay = (transaction?.date ?? today).slice(8, 10);

  const filtered = categories.filter((c) => c.type === type);

  useEffect(() => {
    if (
      categoryId !== NO_CATEGORY &&
      !filtered.some((c) => c.id === categoryId)
    ) {
      setCategoryId(NO_CATEGORY);
    }
  }, [categoryId, filtered]);

  return (
    <form action={formAction} className="flex flex-col gap-4 max-w-lg">
      {transaction ? (
        <input type="hidden" name="id" value={transaction.id} />
      ) : null}
      <input type="hidden" name="type" value={type} />
      <input
        type="hidden"
        name="costCenterId"
        value={type === "despesa" ? costCenterId : NO_CATEGORY}
      />
      <input type="hidden" name="paid" value={paid ? "true" : "false"} />
      <input
        type="hidden"
        name="isRecurrent"
        value={!isEdit && isRecurrent ? "true" : "false"}
      />
      <input
        type="hidden"
        name="foreverRecurrence"
        value={!isEdit && isRecurrent && foreverRecurrence ? "true" : "false"}
      />

      <div className="inline-flex rounded-md border bg-muted/40 p-1 w-fit">
        <button
          type="button"
          onClick={() => setType("receita")}
          className={`px-3 py-1 text-sm rounded ${
            type === "receita"
              ? "bg-background shadow-sm text-emerald-700"
              : "text-muted-foreground"
          }`}
        >
          Receita
        </button>
        <button
          type="button"
          onClick={() => setType("despesa")}
          className={`px-3 py-1 text-sm rounded ${
            type === "despesa"
              ? "bg-background shadow-sm text-rose-700"
              : "text-muted-foreground"
          }`}
        >
          Despesa
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor="date">Data</Label>
          <Input
            id="date"
            name="date"
            type="date"
            defaultValue={transaction?.date ?? today}
            required
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="amount">Valor (R$)</Label>
          <Input
            id="amount"
            name="amount"
            type="text"
            inputMode="decimal"
            pattern="[0-9]+([.,][0-9]{1,2})?"
            placeholder="0,00"
            defaultValue={
              transaction?.amount !== undefined
                ? transaction.amount.toFixed(2).replace(".", ",")
                : ""
            }
            required
          />
        </div>
      </div>

      <div className="grid grid-cols-[13fr_7fr] gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor="description">Descrição</Label>
          <Input
            id="description"
            name="description"
            defaultValue={transaction?.description ?? ""}
            required
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="categoryId">Categoria</Label>
          <Select
            name="categoryId"
            value={categoryId}
            onValueChange={(v) => setCategoryId(v ?? NO_CATEGORY)}
            items={[
              { value: NO_CATEGORY, label: "Sem categoria" },
              ...filtered.map((c) => ({ value: c.id, label: c.name })),
            ]}
          >
            <SelectTrigger id="categoryId" className="w-full">
              <SelectValue placeholder="Sem categoria" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NO_CATEGORY}>Sem categoria</SelectItem>
              {filtered.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {type === "despesa" ? (
        <div className="flex flex-col gap-2">
          <Label htmlFor="costCenterId">Centro de custo</Label>
          <Select
            value={costCenterId}
            onValueChange={(v) => setCostCenterId(v ?? NO_CATEGORY)}
            items={[
              { value: NO_CATEGORY, label: "Sem centro de custo" },
              ...costCenters.map((c) => ({ value: c.id, label: c.name })),
            ]}
          >
            <SelectTrigger id="costCenterId" className="w-full">
              <SelectValue placeholder="Sem centro de custo" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NO_CATEGORY}>Sem centro de custo</SelectItem>
              {costCenters.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      ) : null}

      <div className="flex flex-wrap gap-x-6 gap-y-3">
        {!(isRecurrent && !isEdit) ? (
          <div className="flex items-center gap-3">
            <Switch checked={paid} onCheckedChange={setPaid} id="paid" />
            <Label htmlFor="paid" className="cursor-pointer">
              {type === "receita" ? "Já recebido" : "Já pago"}
            </Label>
          </div>
        ) : null}
        {!isEdit ? (
          <div className="flex items-center gap-3">
            <Switch
              checked={isRecurrent}
              onCheckedChange={setIsRecurrent}
              id="isRecurrent"
            />
            <Label htmlFor="isRecurrent" className="cursor-pointer">
              É recorrente?
            </Label>
          </div>
        ) : null}
      </div>

      {isRecurrent && !isEdit ? (
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2 flex items-center gap-3">
            <Switch
              checked={foreverRecurrence}
              onCheckedChange={setForeverRecurrence}
              id="foreverRecurrence"
            />
            <Label htmlFor="foreverRecurrence" className="cursor-pointer">
              Pra sempre
            </Label>
          </div>
          {foreverRecurrence ? null : (
            <div className="flex flex-col gap-2">
              <Label htmlFor="totalParcels">Parcelas</Label>
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
          <div
            className={`flex flex-col gap-2 ${foreverRecurrence ? "col-span-2" : ""}`}
          >
            <Label htmlFor="dayOfMonth">Dia do mês (1-31)</Label>
            <Input
              id="dayOfMonth"
              name="dayOfMonth"
              type="number"
              min="1"
              max="31"
              defaultValue={defaultDay}
              required
            />
          </div>
          <p className="col-span-2 text-xs text-muted-foreground">
            A 1ª parcela usa a data informada acima. As seguintes seguem o
            dia do mês (nos meses mais curtos, cai no último dia disponível).
            Todas começam como não pagas.
            {foreverRecurrence
              ? " Como é pra sempre, novas parcelas vão sendo criadas automaticamente."
              : ""}
          </p>
        </div>
      ) : null}

      {isEdit && transaction?.recurrenceId ? (
        <p className="text-xs text-muted-foreground">
          Editando a parcela {transaction.parcelNumber} de uma recorrência.
          Alterações aqui não afetam as outras parcelas.
        </p>
      ) : null}

      {state?.error ? (
        <p className="text-sm text-destructive" role="alert">
          {state.error}
        </p>
      ) : null}

      <div className="flex items-center gap-2 pt-2">
        <SubmitButton isEdit={isEdit} />
        {onCancel ? (
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancelar
          </Button>
        ) : (
          <Link href="/" className={buttonVariants({ variant: "ghost" })}>
            Cancelar
          </Link>
        )}
      </div>
    </form>
  );
}

export { NO_CATEGORY };
