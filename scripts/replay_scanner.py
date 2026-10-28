#!/usr/bin/env python3
"""replay_scanner — reproduce los ataques capturados por el honeypot contra targets propios.

Lee requests de la base del honeypot (tabla `requests`), toma los últimos N por fecha
(parametrizable, con filtros opcionales) y los RE-EJECUTA tal cual llegaron —mismo método,
path/query crudo, headers y body— contra uno o varios targets de laboratorio.

Fidelidad: usa http.client (no requests/urllib) para mandar la request line literal, así
preserva payloads en el path como `/cgi-bin/../..%2fetc/passwd` sin que el cliente los
normalice. El Host se reescribe al target (salvo --keep-host); Content-Length se recalcula.

⚠️  USO AUTORIZADO ÚNICAMENTE: esto lanza ataques reales. Ejecutalo solo contra targets
    que te pertenecen / tenés permiso explícito de testear. Pide confirmación salvo --yes.

Requiere: pip install "psycopg[binary]"

Ejemplos:
  # últimos 1000 ataques del honeypot local, contra un target de lab
  python3 scripts/replay_scanner.py --limit 1000 --target http://10.0.0.5

  # varios targets desde archivo, 20 en paralelo, guardando resultados
  python3 scripts/replay_scanner.py --limit 500 --targets-file lab.txt -c 20 -o out.jsonl

  # SOLO ataques que dispararon alertas (alto valor), high+medium, contra el target
  python3 scripts/replay_scanner.py --severity high,medium --limit 500 --target http://10.0.0.5

  # solo ver qué se seleccionaría (sin lanzar nada)
  python3 scripts/replay_scanner.py --limit 50 --target http://10.0.0.5 --dry-run

  # contra la base del SERVER: tunelear antes 'ssh -L 5444:127.0.0.1:5433 <tu-server>'
  python3 scripts/replay_scanner.py --db-port 5444 --db-pass <PASS_SERVER> \\
      --limit 1000 --target http://10.0.0.5

Por default muestra una línea por request con el código de respuesta coloreado (estilo
nuclei). Usá -q/--quiet para ver solo el resumen, o --no-color para desactivar colores.
"""
import argparse
import base64
import http.client
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

# Headers que NO se reenvían: los maneja la conexión / los recalculamos nosotros.
DROP_HEADERS = {"host", "content-length", "transfer-encoding", "connection",
                "proxy-connection", "keep-alive", "upgrade"}

# Colores ANSI para la salida tipo nuclei
ANSI = {"reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
        "green": "\033[32m", "cyan": "\033[36m", "yellow": "\033[33m",
        "red": "\033[31m", "grey": "\033[90m"}


def status_color(res):
    if res["error"]:
        return "red"
    s = res["status"] or 0
    if 200 <= s < 300:
        return "green"
    if 300 <= s < 400:
        return "cyan"
    if 400 <= s < 500:
        return "yellow"
    return "red"


def format_result_line(res, use_color, width=110):
    """Línea estilo nuclei: [STATUS] METHOD uri  (bytes, ms) target"""
    tag = "ERR" if res["error"] else str(res["status"])
    uri = res["uri"] or "/"
    if len(uri) > width:
        uri = uri[:width - 1] + "…"
    meta = (f"{res['error']}" if res["error"]
            else f"{res['resp_bytes']}B {res['elapsed_ms']}ms")
    if use_color:
        col = ANSI[status_color(res)]
        return (f"{col}[{tag:>3}]{ANSI['reset']} {res['method']:<6} {uri}  "
                f"{ANSI['grey']}({meta}) {res['target']}{ANSI['reset']}")
    return f"[{tag:>3}] {res['method']:<6} {uri}  ({meta}) {res['target']}"


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


# --------------------------------------------------------------------------- #
# Selección de requests desde la base del honeypot
# --------------------------------------------------------------------------- #

def fetch_requests(args):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        sys.exit('Falta psycopg. Instalá:  pip install "psycopg[binary]"')

    dsn = args.dsn or (
        f"host={args.db_host} port={args.db_port} dbname={args.db_name} "
        f"user={args.db_user} password={args.db_pass}"
    )
    where, params = [], []
    if args.method:
        methods = [m.strip().upper() for m in args.method.split(",") if m.strip()]
        if methods:
            where.append("method = ANY(%s)")
            params.append(methods)
    if args.path_like:
        where.append("uri ILIKE %s")
        params.append(f"%{args.path_like}%")
    if args.only_body:
        where.append("body IS NOT NULL")
    if args.since:
        where.append("ts >= %s")
        params.append(args.since)
    # Nutrirse de las alertas: solo requests que dispararon una alerta (alto valor).
    if args.from_alerts or args.severity or args.alert_rule:
        sub = ["a.request_id = requests.id"]
        sub_params = []
        if args.severity:
            sevs = [s.strip().lower() for s in args.severity.split(",") if s.strip()]
            sub.append("a.severity = ANY(%s)")
            sub_params.append(sevs)
        if args.alert_rule:
            rules = [r.strip() for r in args.alert_rule.split(",") if r.strip()]
            sub.append("a.rule = ANY(%s)")
            sub_params.append(rules)
        where.append("EXISTS (SELECT 1 FROM alerts a WHERE " + " AND ".join(sub) + ")")
        params.extend(sub_params)
    if not args.include_whitelisted:
        # excluye IPs propias (tabla ip_whitelist) salvo que se pida lo contrario
        where.append("NOT EXISTS (SELECT 1 FROM ip_whitelist w "
                     "WHERE requests.remote_addr <<= w.cidr)")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    cols = "id, ts, scheme, host, method, uri, headers, body, body_encoding"

    if args.no_dedup:
        # tal cual, incluyendo repetidos
        sql = f"SELECT {cols} FROM requests {clause} ORDER BY ts DESC, id DESC LIMIT %s"
        params.append(args.limit)
    else:
        # dedup por (método + uri + body + headers): si varía CUALQUIERA de esos,
        # cuenta como request distinto (así no se pierden variaciones en body/headers).
        # DISTINCT ON se queda con la ocurrencia más reciente de cada combinación;
        # el LIMIT externo toma los N requests ÚNICOS más recientes.
        inner = (
            f"SELECT DISTINCT ON (method, uri, md5(coalesce(body,'')), headers) {cols} "
            f"FROM requests {clause} "
            "ORDER BY method, uri, md5(coalesce(body,'')), headers, ts DESC"
        )
        sql = f"SELECT * FROM ({inner}) u ORDER BY ts DESC, id DESC LIMIT %s"
        params.append(args.limit)

    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(sql, params)
                rows = cur.fetchall()
            except psycopg.errors.UndefinedTable:
                # DB sin la tabla ip_whitelist (schema de alertas no aplicado): reintenta
                # sin la exclusión. Rehacemos la query quitando esa condición.
                conn.rollback()
                sql2 = sql.replace(
                    "NOT EXISTS (SELECT 1 FROM ip_whitelist w "
                    "WHERE requests.remote_addr <<= w.cidr)", "true")
                cur.execute(sql2, params)
                rows = cur.fetchall()

    if args.chrono:
        rows.reverse()  # replay en el orden en que llegaron (más viejo primero)
    return rows


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #

def parse_target(raw, default_scheme):
    raw = raw.strip()
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"
    u = urlsplit(raw)
    scheme = u.scheme or default_scheme
    host = u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    if not host:
        raise ValueError(f"target inválido: {raw!r}")
    return {"scheme": scheme, "host": host, "port": port, "raw": raw}


def load_targets(args):
    targets = []
    for t in args.target or []:
        targets.append(parse_target(t, args.scheme))
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(parse_target(line, args.scheme))
    return targets


def host_header(t):
    default = 443 if t["scheme"] == "https" else 80
    return t["host"] if t["port"] == default else f"{t['host']}:{t['port']}"


# --------------------------------------------------------------------------- #
# Replay de un request contra un target
# --------------------------------------------------------------------------- #

def decode_body(req):
    enc, body = req.get("body_encoding"), req.get("body")
    if body is None:
        return None
    if enc == "base64":
        try:
            return base64.b64decode(body)
        except Exception:
            return body.encode("utf-8", "replace")
    return body.encode("utf-8", "replace")


def replay_one(req, target, args):
    path = req.get("uri") or "/"
    method = (req.get("method") or "GET").upper()
    body = decode_body(req)
    result = {"request_id": req["id"], "target": target["raw"], "method": method,
              "uri": path, "status": None, "resp_bytes": None, "elapsed_ms": None,
              "error": None}
    t0 = time.monotonic()
    conn = None
    try:
        if target["scheme"] == "https":
            ctx = ssl.create_default_context()
            if not args.verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(target["host"], target["port"],
                                               timeout=args.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(target["host"], target["port"],
                                              timeout=args.timeout)
        # request line literal (preserva el path crudo)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)

        headers = req.get("headers") or {}
        for k, v in headers.items():
            if k.lower() in DROP_HEADERS:
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            try:
                conn.putheader(k, str(v))
            except (ValueError, UnicodeEncodeError):
                continue  # header con bytes inválidos: lo salteamos
        # Host del target (salvo que se pida conservar el original)
        if args.keep_host and headers.get("host"):
            conn.putheader("Host", headers["host"])
        else:
            conn.putheader("Host", host_header(target))
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))

        conn.endheaders(message_body=body)
        resp = conn.getresponse()
        data = resp.read()
        result["status"] = resp.status
        result["resp_bytes"] = len(data)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (OSError, http.client.HTTPException) as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        result["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return result


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Reproduce los ataques capturados por el honeypot contra targets propios.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    # selección
    p.add_argument("--limit", type=int, default=100,
                   help="cuántos requests replicar (últimos N ÚNICOS por fecha). Default 100")
    p.add_argument("--method",
                   help="filtrar por método(s), coma-separado. Ej: --method POST  o  "
                        "--method GET,HEAD. Replica solo esos.")
    p.add_argument("--path-like", help="filtrar: uri contiene este texto (ILIKE)")
    p.add_argument("--only-body", action="store_true", help="solo requests con body")
    p.add_argument("--from-alerts", action="store_true",
                   help="replicar SOLO requests que dispararon una alerta (alto valor)")
    p.add_argument("--severity",
                   help="con --from-alerts: filtrar por severidad(es) de la alerta, "
                        "coma-sep (ej. high,medium). Implica --from-alerts.")
    p.add_argument("--alert-rule",
                   help="con --from-alerts: filtrar por regla(s) de alerta, coma-sep "
                        "(ej. sqli,rce_cmd_injection). Implica --from-alerts.")
    p.add_argument("--since", help="solo requests con ts >= (ej. '2026-10-25')")
    p.add_argument("--no-dedup", action="store_true",
                   help="NO deduplicar (por default se colapsan los idénticos por "
                        "método+uri+body+headers; una variación en cualquiera = request distinto)")
    p.add_argument("--chrono", action="store_true",
                   help="replay en orden cronológico (más viejo primero)")
    p.add_argument("--include-whitelisted", action="store_true",
                   help="NO excluir las IPs de ip_whitelist (por default se excluyen)")
    # targets
    p.add_argument("--target", action="append", help="target (repetible). Ej http://10.0.0.5:8080")
    p.add_argument("--targets-file", help="archivo con un target por línea (# = comentario)")
    p.add_argument("--scheme", default="http", help="scheme por defecto si el target no lo trae")
    p.add_argument("--keep-host", action="store_true",
                   help="conservar el header Host original en vez de reescribirlo al target")
    # ejecución
    p.add_argument("-c", "--concurrency", type=int, default=10, help="requests en paralelo")
    p.add_argument("--timeout", type=float, default=10.0, help="timeout por request (s)")
    p.add_argument("--verify", action="store_true", help="verificar TLS (default: no, lab)")
    p.add_argument("-o", "--output", help="guardar resultados como JSONL")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="no mostrar request-por-request, solo el resumen final")
    p.add_argument("--no-color", action="store_true", help="salida sin colores ANSI")
    p.add_argument("--dry-run", action="store_true", help="mostrar qué se enviaría, sin enviar")
    p.add_argument("--list", action="store_true", help="listar los requests seleccionados y salir")
    p.add_argument("--yes", action="store_true", help="no pedir confirmación")
    # base de datos
    p.add_argument("--dsn", help="DSN completo de psycopg (pisa los --db-*)")
    p.add_argument("--db-host", default=os.getenv("DB_HOST", "127.0.0.1"))
    p.add_argument("--db-port", default=os.getenv("DB_PORT", "5433"))
    p.add_argument("--db-name", default=os.getenv("DB_NAME", "honeypot"))
    p.add_argument("--db-user", default=os.getenv("DB_USER", "honeypot"))
    p.add_argument("--db-pass", default=os.getenv("DB_PASS", "honeypot_dev_pass"))
    return p


def main():
    args = build_parser().parse_args()

    reqs = fetch_requests(args)
    if not reqs:
        sys.exit("No hay requests que matcheen el criterio.")

    if args.list:
        for r in reqs:
            eprint(f"#{r['id']}  {r['ts']}  {r['method']:7} {r['uri'][:90]}")
        eprint(f"\n{len(reqs)} requests seleccionados.")
        return

    targets = load_targets(args)
    if not targets:
        sys.exit("Especificá al menos --target o --targets-file.")

    total = len(reqs) * len(targets)
    dedup_nota = "sin dedup" if args.no_dedup else "únicos por método+uri+body+headers"
    eprint(f"Seleccionados {len(reqs)} requests ({dedup_nota}) × {len(targets)} "
           f"target(s) = {total} envíos.")

    if args.dry_run:
        for t in targets:
            for r in reqs[:50]:
                eprint(f"  [{t['raw']}] {r['method']} {r['uri'][:80]}")
        if total > 50:
            eprint(f"  … (dry-run muestra hasta 50 por target)")
        eprint("DRY-RUN: no se envió nada.")
        return

    # confirmación de seguridad
    eprint("\n⚠️  Vas a REPRODUCIR ataques reales contra:")
    for t in targets:
        eprint(f"     - {t['raw']}")
    eprint("   Asegurate de tener autorización sobre estos targets.")
    if not args.yes:
        if not sys.stdin.isatty():
            sys.exit("Abortado: se requiere --yes en modo no interactivo.")
        if input("   ¿Continuar? escribí 'si': ").strip().lower() not in ("si", "sí", "yes", "y"):
            sys.exit("Abortado.")

    results, done = [], 0
    outfh = open(args.output, "w", encoding="utf-8") if args.output else None
    use_color = sys.stdout.isatty() and not args.no_color
    t_start = time.monotonic()
    tasks = [(r, t) for t in targets for r in reqs]
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(replay_one, r, t, args) for r, t in tasks]
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            if outfh:
                outfh.write(json.dumps(res, default=str) + "\n")
            done += 1
            if args.quiet:
                if done % 50 == 0 or done == total:
                    eprint(f"\r  {done}/{total} enviados…", end="")
            else:
                # una línea por request, estilo nuclei (a stdout, flush para verlo en vivo)
                print(f"{format_result_line(res, use_color)} "
                      f"{ANSI['grey'] if use_color else ''}[{done}/{total}]"
                      f"{ANSI['reset'] if use_color else ''}", flush=True)
    if args.quiet:
        eprint()
    if outfh:
        outfh.close()

    # resumen
    elapsed = time.monotonic() - t_start
    by_status, errors = {}, 0
    for r in results:
        if r["error"]:
            errors += 1
        else:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    eprint(f"\n=== Resumen ({elapsed:.1f}s, {total/elapsed:.0f} req/s) ===")
    for st in sorted(by_status):
        eprint(f"  HTTP {st}: {by_status[st]}")
    if errors:
        eprint(f"  errores/timeouts: {errors}")
    if args.output:
        eprint(f"  resultados -> {args.output}")


if __name__ == "__main__":
    main()
