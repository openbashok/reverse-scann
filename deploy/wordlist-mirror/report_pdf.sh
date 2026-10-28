#!/bin/sh
# Corre en el FILESERVER (always-on). Reporte DIARIO del honeypot en PDF:
#   1) PULL del HTML del reporte desde el honeypot (comando forzado, modo "report")
#   2) HTML -> PDF con un Gotenberg por la red privada
#   3) envío por Mailgun con el PDF adjunto
#
# Reusa un Gotenberg existente SOLO como servicio de render (stateless); el honeypot
# nunca toca la red privada (solo genera el HTML).
#
# Config de infra FUERA del repo (es público). En el fileserver, ~/.reverse-scann.conf (600):
#   HONEYPOT=root@<ip-honeypot>
#   GOTENBERG=http://<host-gotenberg>:3000/forms/chromium/convert/html
#   MAIL_TO=<destinatario>
# La key de Mailgun va en ~/.mailgun.cred (600). Ninguno se commitea.
set -eu
HONEYPOT=""; GOTENBERG=""; MAIL_TO=""
[ -f "$HOME/.reverse-scann.conf" ] && . "$HOME/.reverse-scann.conf"
KEY="$HOME/.ssh/id_wordlist_mirror"
MAILGUN_API="https://api.mailgun.net/v3/m.openbash.com/messages"
MAIL_FROM="OpenBash reverse-scann <alertas@m.openbash.com>"
MAILGUN_KEY=""
[ -f "$HOME/.mailgun.cred" ] && . "$HOME/.mailgun.cred"
: "${HONEYPOT:?falta HONEYPOT en ~/.reverse-scann.conf}"
: "${GOTENBERG:?falta GOTENBERG en ~/.reverse-scann.conf}"
: "${MAIL_TO:?falta MAIL_TO (en ~/.reverse-scann.conf o ~/.mailgun.cred)}"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
HTML="$TMP/index.html"; PDF="$TMP/report.pdf"

# 1) HTML del reporte (forced command -> modo report). Saca la línea marcadora ===FILE:.
ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEY" "$HONEYPOT" report 2>/dev/null \
  | sed '1{/^===FILE:/d}' > "$HTML"
if [ "$(wc -c < "$HTML")" -lt 2000 ] || ! grep -qi "honeypot" "$HTML"; then
  echo "$(date -u +%F\ %T) pull de reporte inválido (dashboard caído?), abort" >&2; exit 1
fi

# 2) HTML -> PDF (A4) con Gotenberg
code=$(curl -s --max-time 60 \
  --form "files=@${HTML};filename=index.html" \
  --form "paperWidth=8.27" --form "paperHeight=11.7" \
  --form "printBackground=true" \
  -o "$PDF" -w '%{http_code}' "$GOTENBERG")
if [ "$code" != "200" ] || [ "$(head -c4 "$PDF" 2>/dev/null)" != "%PDF" ]; then
  echo "$(date -u +%F\ %T) Gotenberg falló (HTTP $code), abort" >&2; exit 1
fi

# 3) envío por Mailgun con el PDF adjunto
[ -n "$MAILGUN_KEY" ] || { echo "$(date -u +%F\ %T) sin MAILGUN_KEY, no envío" >&2; exit 1; }
DAY=$(date -u +%d/%m/%Y)
BODY='<p style="font-family:Arial,sans-serif;color:#1a1a1a">Adjunto el <b>reporte diario de actividad del honeypot reverse-scann</b> (últimas 24 h), en PDF con formato consistente con los reportes de pentest.<br><br>Generado automáticamente - OpenBash reverse-scann.</p>'
mc=$(curl -s --max-time 60 --user "api:${MAILGUN_KEY}" "$MAILGUN_API" \
  -F from="$MAIL_FROM" -F to="$MAIL_TO" \
  -F subject="[reverse-scann] Reporte diario $DAY" \
  --form-string "html=${BODY}" \
  -F attachment=@"${PDF}" \
  -o /dev/null -w '%{http_code}')
echo "$(date -u +%F\ %T) report enviado (mailgun HTTP $mc, pdf $(wc -c < "$PDF") bytes)"

# 4) Publicación de la página pública (GitHub Pages) — opcional y best-effort: si falla,
#    NO afecta el mail. Se activa solo si ~/.reverse-scann.conf define PUBLIC_REPORT_DIR
#    (clone con remote de deploy key de escritura al repo público).
if [ -n "${PUBLIC_REPORT_DIR:-}" ] && [ -d "${PUBLIC_REPORT_DIR}/.git" ]; then
  PUB="$TMP/public.html"
  ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEY" "$HONEYPOT" report-public 2>/dev/null > "$PUB" || true
  if [ "$(wc -c < "$PUB" 2>/dev/null || echo 0)" -ge 2000 ] && grep -qi "honeypot" "$PUB" 2>/dev/null; then
    cp "$PUB" "${PUBLIC_REPORT_DIR}/index.html"
    if ( cd "$PUBLIC_REPORT_DIR" && git add -A && { git diff --cached --quiet || git commit -q -m "update $(date -u +%F)"; } && git push -q origin main ); then
      echo "$(date -u +%F\ %T) página pública actualizada"
    else
      echo "$(date -u +%F\ %T) push de página pública falló (el mail igual salió)" >&2
    fi
  else
    echo "$(date -u +%F\ %T) pull público inválido, no publico (el mail igual salió)" >&2
  fi
fi

[ "$mc" = "200" ] || exit 1
