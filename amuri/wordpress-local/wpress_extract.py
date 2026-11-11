#!/usr/bin/env python3
"""Extrai um backup .wpress (All-in-One WP Migration) sem precisar do plugin.

Uso: python3 -I wpress_extract.py <arquivo.wpress> <pasta-destino>

Formato: sequência de [header 4377 bytes][conteúdo]. Header = nome (255) +
tamanho (14) + mtime (12) + pasta (4096), tudo preenchido com \\0.
O último bloco é uma assinatura cujo "tamanho" aponta para fora do arquivo;
é por ele que paramos.
"""
import os
import sys

HDR = 4377


def main(src, out):
    total = os.path.getsize(src)
    n = 0
    with open(src, "rb") as f:
        while True:
            pos = f.tell()
            h = f.read(HDR)
            if len(h) < HDR:
                break
            size = int(h[255:269].split(b"\0")[0] or 0)
            if pos + HDR + size > total:  # bloco final de assinatura
                break
            name = h[:255].split(b"\0")[0].decode()
            prefix = h[281:].split(b"\0")[0].decode().strip()
            rel = os.path.normpath(os.path.join(prefix, name))
            if rel.startswith("..") or os.path.isabs(rel):
                f.seek(size, 1)
                continue
            dst = os.path.join(out, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as o:
                left = size
                while left:
                    chunk = f.read(min(left, 1 << 20))
                    o.write(chunk)
                    left -= len(chunk)
            n += 1
    print(f"{n} arquivos extraídos em {out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
