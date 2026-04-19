"use client";

import { useActionState, useState } from "react";
import { useFormStatus } from "react-dom";
import Link from "next/link";
import type { Category, Transaction } from "@/lib/db/schema";
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
    <Button type="submit" disabled={pending}>
      {pending ? "Salvando..." : isEdit ? "Salvar alterações" : "Criar"}
    </Button>
  );
}

export function TransactionForm({
  categories,
  transaction,
}: {
  categories: Category[];
  transaction?: Transaction;
}) {
  const isEdit = Boolean(transaction);
  const action = isEdit ? updateTransaction : createTransaction;
  const [state, formAction] = useActionState<FormState, FormData>(
    action,
    undefined,
  );

  const [type, setType] = useState<"receita" | "despesa">(
    transaction?.type ?? "despesa",
  );
  const [paid, setPaid] = useState<boolean>(transaction?.paid ?? false);
  const [isRecurrent, setIsRecurrent] = useState(false);
  const today = new Date().toISOString().slice(0, 10);
  const defaultDay = (transaction?.date ?? today).slice(8, 10);

  const filtered = categories.filter((c) => c.type === type);

  return (
    <form action={formAction} className="flex flex-col gap-4 max-w-lg">
      {transaction ? (
        <input type="hidden" name="id" value={transaction.id} />
      ) : null}
      <input type="hidden" name="type" value={type} />
      <input type="hidden" name="paid" value={paid ? "true" : "false"} />
      <input
        type="hidden"
        name="isRecurrent"
        value={!isEdit && isRecurrent ? "true" : "false"}
      />

      <div className="flex flex-col gap-2">
        <Label>Tipo</Label>
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
            type="number"
            step="0.01"
            min="0"
            placeholder="0,00"
            defaultValue={transaction?.amount ?? ""}
            required
          />
        </div>
      </div>

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
          defaultValue={transaction?.categoryId ?? NO_CATEGORY}
        >
          <SelectTrigger id="categoryId">
            <SelectValue />
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
        {filtered.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            Nenhuma categoria de {type}. Crie em{" "}
            <Link href="/categorias" className="underline">
              Categorias
            </Link>
            .
          </p>
        ) : null}
      </div>

      {!(isRecurrent && !isEdit) ? (
        <div className="flex items-center gap-3">
          <Switch checked={paid} onCheckedChange={setPaid} id="paid" />
          <Label htmlFor="paid" className="cursor-pointer">
            {type === "receita" ? "Já recebido" : "Já pago"}
          </Label>
        </div>
      ) : null}

      {!isEdit ? (
        <div className="rounded-md border p-4 flex flex-col gap-4">
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
          {isRecurrent ? (
            <div className="grid grid-cols-2 gap-4">
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
              <div className="flex flex-col gap-2">
                <Label htmlFor="dayOfMonth">Dia do mês (1-28)</Label>
                <Input
                  id="dayOfMonth"
                  name="dayOfMonth"
                  type="number"
                  min="1"
                  max="28"
                  defaultValue={defaultDay}
                  required
                />
              </div>
              <p className="col-span-2 text-xs text-muted-foreground">
                A 1ª parcela usa a data informada acima. As seguintes seguem o
                dia do mês. Todas começam como não pagas.
              </p>
            </div>
          ) : null}
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

      <div className="flex gap-2 pt-2">
        <Link href="/" className={buttonVariants({ variant: "ghost" })}>
          Cancelar
        </Link>
        <SubmitButton isEdit={isEdit} />
      </div>
    </form>
  );
}

export { NO_CATEGORY };
