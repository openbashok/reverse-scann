#!/bin/sh
# Corre en el HONEYPOT (reverse-scann). Export restringido: imprime SOLO lo que pide
# el fileserver desde el dashboard loopback, nada más. Se invoca como COMANDO FORZADO:
#
#   command="/usr/local/bin/wordlist-export.sh",no-port-forwarding,no-agent-forwarding,\
#   no-X11-forwarding,no-pty ssh-ed25519 AAAA... wordlist-mirror@fileserver
#
# El forced command ignora lo que mande el cliente como comando real, pero lo deja en
# $SSH_ORIGINAL_COMMAND. Lo usamos para elegir QUÉ exportar (wordlists o el reporte),
# sin aflojar la restricción: el script solo puede emitir una de esas dos cosas.
#   ssh ... reverse-scann                -> wordlists (default; lo usa el mirror horario)
#   ssh ... reverse-scann report         -> HTML estilo-pentest (A4) p/ PDF (report_pdf diario)
#   ssh ... reverse-scann report-public  -> HTML público (web) p/ GitHub Pages (diario)
#
# El honeypot no tiene credenciales hacia la infra: el fileserver inicia el pull.

case "${SSH_ORIGINAL_COMMAND:-}" in
  report)
    # HTML estilo-pentest (A4) listo para que Gotenberg lo pase a PDF.
    echo "===FILE:report.html==="
    curl -s "http://localhost:8088/api/report?scope=private&style=pdf&hours=24"
    ;;
  report-public)
    # HTML público (agregados, sin identidad del sensor) para publicar en Pages. Crudo.
    curl -s "http://localhost:8088/api/report?scope=public&style=web&hours=24"
    ;;
  *)
    emit() { echo "===FILE:$1==="; curl -s "http://localhost:8088/api/wordlist?$2"; }
    emit paths        "range=all&mode=paths&min_count=1&strip_slash=1"
    emit paths-common    "range=all&mode=paths&min_count=3&strip_slash=1"
    emit paths-top1000   "range=all&mode=paths&min_count=1&top=1000&strip_slash=1"    # top 1000 por frecuencia (tope duro)
    emit paths-top5000   "range=all&mode=paths&min_count=1&top=5000&strip_slash=1"    # top 5000
    emit paths-top10000  "range=all&mode=paths&min_count=1&top=10000&strip_slash=1"   # top 10000
    emit files        "range=all&mode=files&min_count=2&strip_slash=1"
    emit segments     "range=all&mode=segments&min_count=2&strip_slash=1"
    # sensitive: paths tipo secreto/config (enriquece el sensitive_paths del scanner). Acotado top 500 por freq.
    echo "===FILE:sensitive==="
    curl -s "http://localhost:8088/api/wordlist?range=all&mode=paths&min_count=2&strip_slash=1" \
      | grep -iE '\.env|\.git|\.svn|\.aws|\.ssh|\.kube|\.npmrc|htpasswd|htaccess|config|secret|credential|backup|dump|\.sql|actuator|heapdump|phpinfo|server-status|id_rsa|wp-config|\.bak|\.key|\.pem|\.ya?ml|web\.config|docker-compose' \
      | head -500
    emit uris             "range=all&mode=uris&min_count=1&strip_slash=1"           # URI completa (path+query)
    emit uris-common      "range=all&mode=uris&min_count=3&strip_slash=1"           # idem, curado (visto >=3)
    emit uris-safe        "range=all&mode=uris-safe&min_count=1&strip_slash=1"      # URI completa shell-safe
    emit uris-safe-common "range=all&mode=uris-safe&min_count=3&strip_slash=1"      # idem, curado + shell-safe
    ;;
esac
