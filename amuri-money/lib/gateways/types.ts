export type IuguDetailItem = {
  cliente: string;
  compraEm: string;
  liquidaEm: string;
  parcela: number;
  totalParcelas: number;
  valor: number;
  metodo: string;
};

export type StripeDetailItem = {
  cliente: string;
  produto: string;
  cobrancaEm: string;
  disponivelEm: string;
  valor: number;
  assinaturaDesde: string;
  cancelaEm: string | null;
  parcelasRestantes: number | null;
};

export type StripeBookItem = {
  cliente: string;
  produto: string;
  cobrancaEm: string;
  disponivelEm: string;
  valor: number;
};

export type VirtualRowDetail =
  | { kind: "iugu"; items: IuguDetailItem[] }
  | { kind: "stripe"; items: StripeDetailItem[] }
  | { kind: "stripe-books"; items: StripeBookItem[] };
