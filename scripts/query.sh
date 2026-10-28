#!/bin/sh
# Consultas rápidas sobre los ataques capturados.
# Uso:
#   ./scripts/query.sh            -> resumen (totales, top IPs, top paths, top user-agents)
#   ./scripts/query.sh last [N]   -> últimas N requests (default 20)
#   ./scripts/query.sh ip <addr>  -> todas las requests de una IP
#   ./scripts/query.sh sql "..."  -> SQL arbitrario
#   ./scripts/query.sh psql       -> shell psql interactivo

cd "$(dirname "$0")/.." || exit 1

PSQL="docker compose exec -T db psql -U ${DB_USER:-honeypot} -d ${DB_NAME:-honeypot}"

case "$1" in
  last)
    N="${2:-20}"
    $PSQL -c "SELECT id, ts, remote_addr, method, status, left(uri, 80) AS uri
              FROM requests ORDER BY id DESC LIMIT $N;"
    ;;
  ip)
    [ -z "$2" ] && { echo "uso: $0 ip <addr>"; exit 1; }
    $PSQL -c "SELECT id, ts, method, status, uri, user_agent
              FROM requests WHERE remote_addr = '$2' ORDER BY id;"
    ;;
  sql)
    [ -z "$2" ] && { echo "uso: $0 sql \"SELECT ...\""; exit 1; }
    $PSQL -c "$2"
    ;;
  psql)
    docker compose exec db psql -U "${DB_USER:-honeypot}" -d "${DB_NAME:-honeypot}"
    ;;
  *)
    $PSQL <<'EOF'
\echo '=== Totales ==='
SELECT count(*) AS requests_totales,
       count(DISTINCT remote_addr) AS ips_distintas,
       count(*) FILTER (WHERE body IS NOT NULL) AS con_body
FROM requests;

\echo '=== Top 15 IPs ==='
SELECT remote_addr, count(*) AS hits, min(ts) AS primera, max(ts) AS ultima
FROM requests GROUP BY remote_addr ORDER BY hits DESC LIMIT 15;

\echo '=== Top 20 paths ==='
SELECT path, count(*) AS hits FROM requests GROUP BY path ORDER BY hits DESC LIMIT 20;

\echo '=== Top 10 user-agents ==='
SELECT coalesce(user_agent, '(sin UA)') AS user_agent, count(*) AS hits
FROM requests GROUP BY 1 ORDER BY hits DESC LIMIT 10;

\echo '=== Metodos ==='
SELECT method, count(*) FROM requests GROUP BY method ORDER BY count DESC;
EOF
    ;;
esac
