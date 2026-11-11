#!/bin/bash
# Importa um backup .wpress de programas.amuri.com.br para um site do LocalWP.
# Uso: ./importar.sh <arquivo.wpress> [nome-do-site-no-local]
# O site precisa existir no Local e estar rodando (Start site).
set -euo pipefail

WPRESS="${1:?uso: ./importar.sh <arquivo.wpress> [nome-do-site]}"
SITE="${2:-programas-amuri}"
PROD_URL="https://programas.amuri.com.br"
HERE="$(cd "$(dirname "$0")" && pwd)"
LS="$HOME/Library/Application Support/Local"

# --- localizar o site e os binários do Local ---------------------------------
read -r SITE_ID DOMAIN SITE_PATH < <(python3 -I - "$LS/sites.json" "$SITE" <<'EOF'
import json, os, sys
d = json.load(open(sys.argv[1]))
for k, v in d.items():
    if v.get("name") == sys.argv[2]:
        print(k, v["domain"], os.path.expanduser(v["path"])); break
else:
    sys.exit(f"site '{sys.argv[2]}' não encontrado no Local")
EOF
)
LOCAL_URL="http://$DOMAIN"
PUB="$SITE_PATH/app/public"
MYSQL="$(ls "$LS"/lightning-services/mysql-*/bin/darwin-arm64/bin/mysql | tail -1)"
PHP="$(ls "$LS"/lightning-services/php-*/bin/darwin-arm64/bin/php | tail -1)"
INI="$LS/run/$SITE_ID/conf/php/php.ini"
SOCK="$LS/run/$SITE_ID/mysql/mysqld.sock"
WPCLI="/Applications/Local.app/Contents/Resources/extraResources/bin/wp-cli/wp-cli.phar"
[ -S "$SOCK" ] || { echo "MySQL do site não está rodando — dê Start site no Local."; exit 1; }
if [ -n "$(git -C "$HERE/../tema" status --porcelain -- . 2>/dev/null)" ]; then
  echo "amuri/tema tem alterações sem commit. Faça commit antes: o import sobrescreve o tema."; exit 1
fi
wp() { "$PHP" -c "$INI" -d memory_limit=1024M "$WPCLI" --path="$PUB" "$@" 2>&1 | grep -v -E "Deprecated|^PHP " || true; }
sql() { "$MYSQL" --socket="$SOCK" -uroot -proot "$@" 2>&1 | grep -v "Using a password" || true; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT   # o dump tem dados de clientes: não deixar sobrar

echo "1/6 extraindo $WPRESS"
python3 -I "$HERE/wpress_extract.py" "$WPRESS" "$TMP"

echo "2/6 copiando tema, plugins e uploads"
# fora de propósito: wpvividbackups, wpvivid_staging, litespeed, object-cache.php, debug.log
for d in plugins uploads mu-plugins languages; do
  [ -d "$TMP/$d" ] && rsync -a --delete "$TMP/$d/" "$PUB/wp-content/$d/"
done
# Temas: o "amuri" vive no repositório (amuri/tema) e o Local enxerga via link simbólico.
# --exclude='/amuri' impede o rsync de trocar o link por uma pasta comum.
rsync -a --delete --exclude='/amuri' "$TMP/themes/" "$PUB/wp-content/themes/"
REPO_TEMA="$(cd "$HERE/../tema" && pwd)"
LINK="$PUB/wp-content/themes/amuri"
if [ ! -L "$LINK" ]; then
  [ -e "$LINK" ] && mv "$LINK" "$SITE_PATH/tema-amuri-backup-$(date +%Y%m%d%H%M)"
  ln -s "$REPO_TEMA" "$LINK"
fi
# Código de produção por cima do repositório: depois do import, `git status` em amuri/tema
# mostra o que foi alterado direto no servidor. Os excludes preservam o setup de build.
rsync -a --delete --exclude='node_modules/' --exclude='gulp-config.json' \
  "$TMP/themes/amuri/" "$REPO_TEMA/"
echo "  tema de produção copiado em $REPO_TEMA. Confira com: git -C \"$REPO_TEMA\" status"

echo "3/6 importando banco"
sql -e "DROP DATABASE IF EXISTS local; CREATE DATABASE local DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;"
# sql_mode vazio: o MySQL 8 do Local recusa as datas 0000-00-00 que o MariaDB de produção aceita
{ echo "SET SESSION sql_mode=''; SET FOREIGN_KEY_CHECKS=0;"; sed 's/SERVMASK_PREFIX_/wp_/g' "$TMP/database.sql"; } \
  | sql --max_allowed_packet=512M local

echo "4/6 trocando URLs e tema"
wp --skip-plugins --skip-themes option update template amuri
wp --skip-plugins --skip-themes option update stylesheet amuri
wp --skip-plugins --skip-themes search-replace "$PROD_URL" "$LOCAL_URL" --all-tables --precise --report-changed-only | tail -1
wp --skip-plugins --skip-themes search-replace "${PROD_URL//\//\\/}" "${LOCAL_URL//\//\\/}" --all-tables --report-changed-only | tail -1

echo "5/6 wp-config e plugins"
# o tema (header.php) exige essa constante; em produção ela vale 'production' e liga o Analytics
python3 -I - "$PUB/wp-config.php" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
if "AMBIENT_VAR_DEF" not in s:
    open(p, "w").write(s.replace("$table_prefix", "define( 'AMBIENT_VAR_DEF', 'local' );\n\n$table_prefix", 1))
EOF
# Só os plugins que não falam com o mundo externo. Ficam desligados: iugu-woocommerce,
# woocommerce-gateway-stripe, wp-mail-smtp, pixelyoursite, microsoft-clarity,
# insert-headers-and-footers, litespeed-cache, miniorange-secure-mcp-server, wpvivid, all-in-one.
wp --skip-themes plugin activate advanced-custom-fields-pro woocommerce \
  woocommerce-extra-checkout-fields-for-brazil autocomplete-address-for-woocommerce \
  sensei-lms sensei-pro woocommerce-memberships safe-svg simple-author-box \
  stackable-ultimate-gutenberg-blocks-premium duplicate-post | grep -E "Success|Error|Warning: Plugin"

echo "6/6 testando"
wp rewrite flush >/dev/null; wp cache flush >/dev/null
curl -s -o /dev/null -w "  $LOCAL_URL/dsm/ -> HTTP %{http_code}\n" "$LOCAL_URL/dsm/"
echo "Pronto. Painel: $LOCAL_URL/wp-admin (mesmo login de produção)."
echo "Lembre de apagar o backup do servidor em All-in-One WP Migration > Backups."
