#!/bin/sh
# Corre en el FILESERVER (always-on, monta el NFS). Espejo del diccionario de vectores:
#   1) PULL read-only del honeypot vía comando forzado (el fileserver inicia la conexión)
#   2) escribe las wordlists al NFS (para que nodo-dev las lea de /mnt/nfs/wordlists)
#   3) commit + push al repo público openbashok/attack-vectors (deploy key read-write)
#
# Seguridad: el honeypot (caja más atacada) NO tiene credenciales hacia la infra. Si lo
# comprometen, el daño queda ahí. El fileserver es el único con la mirror key y el deploy key.
set -eu
# Infra específica FUERA del repo (es público). En el fileserver, ~/.reverse-scann.conf (600):
#   HONEYPOT=root@<ip-honeypot>   MAIL_TO=<destinatario>
HONEYPOT=""; MAIL_TO=""
[ -f "$HOME/.reverse-scann.conf" ] && . "$HOME/.reverse-scann.conf"
: "${HONEYPOT:?falta HONEYPOT en ~/.reverse-scann.conf}"
KEY="$HOME/.ssh/id_wordlist_mirror"
REPO="$HOME/attack-vectors"          # clone con remote git@github-wordlist:openbashok/attack-vectors
NFS="/var/nfs/wordlists"
# Umbral de tamaño "exagerado" para paths.txt (default 200 MB). Sin retención: no se borra
# nada; solo se alerta por mail si algo se dispara (posible flood/envenenamiento).
MAX_BYTES="${MAX_BYTES:-209715200}"
MARK="$HOME/.wordlist_oversize"
# Credenciales de Mailgun fuera del repo (el repo es público). Archivo 600 en el fileserver:
#   MAILGUN_KEY=...  MAIL_TO=...  (opcionales: MAILGUN_API, MAIL_FROM)
MAILGUN_API="https://api.mailgun.net/v3/m.openbash.com/messages"
MAIL_FROM="alertas@m.openbash.com"
MAILGUN_KEY=""
[ -f "$HOME/.mailgun.cred" ] && . "$HOME/.mailgun.cred"
send_mailgun() {
  [ -n "$MAILGUN_KEY" ] || { echo "sin MAILGUN_KEY, no alerto" >&2; return 0; }
  curl -s --user "api:${MAILGUN_KEY}" "$MAILGUN_API" \
    -F from="$MAIL_FROM" -F to="$MAIL_TO" -F subject="$1" --form-string text="$2" >/dev/null || true
}
TMP=$(mktemp); trap "rm -f $TMP" EXIT

ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEY" "$HONEYPOT" > "$TMP" 2>/dev/null

# sanity: deben venir los 4 bloques y contenido mínimo (si el dashboard está caído, abortar
# sin pisar los archivos buenos con vacío)
if [ "$(grep -c "^===FILE:" "$TMP")" -lt 4 ] || [ "$(wc -l < "$TMP")" -lt 50 ]; then
  echo "pull invalido (dashboard caido?), abort" >&2; exit 1
fi

# sanitiza: saca bytes de control y líneas vacías / demasiado largas (anti-envenenamiento)
sanitize() { LC_ALL=C tr -d "\000-\011\013\014\016-\037" | awk "length>0 && length<=512"; }

mkdir -p "$NFS"
for name in paths paths-common files segments uris uris-safe; do
  awk -v n="$name" "\$0==\"===FILE:\"n\"===\"{g=1;next} /^===FILE:/{g=0} g{print}" "$TMP" \
    | sanitize > "$REPO/wordlists/$name.txt"
  cp "$REPO/wordlists/$name.txt" "$NFS/$name.txt"
done
cp "$REPO/wordlists/paths-common.txt" "$NFS/latest.txt"

# Control de tamaño: alerta por mail SOLO en la transición a "exagerado" (no spamea diario).
SZ=$(wc -c < "$REPO/wordlists/paths.txt")
if [ "$SZ" -gt "$MAX_BYTES" ]; then
  if [ ! -f "$MARK" ]; then
    send_mailgun "[attack-vectors] wordlist exagerada: paths.txt $SZ bytes" \
"paths.txt creció a $SZ bytes ($(wc -l < "$REPO/wordlists/paths.txt") líneas), por encima del
umbral de $MAX_BYTES bytes. Posible flood / envenenamiento del honeypot. No se borró nada;
revisá la generación y el tráfico. Host: $(hostname) · $(date -u)"
    touch "$MARK"
    echo "ALERTA enviada: paths.txt $SZ > $MAX_BYTES"
  fi
else
  rm -f "$MARK"   # volvió a la normalidad → rearmar la alerta
fi

cd "$REPO"
git add -A   # incluye archivos NUEVOS (git diff --quiet solo veía los ya trackeados)
if ! git diff --cached --quiet; then
  git commit -q -m "update: $(date -u +%F) (auto-harvest)"
  git push -q origin main && echo "pushed $(date -u +%F)"
else
  echo "sin cambios"
fi
