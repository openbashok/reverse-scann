#!/usr/bin/env python3
"""Dashboard de inspección y configuración del honeypot reverse-scann.

- Inspección (solo lectura) de la tabla `requests`.
- Configuración de "personas" (identidad del honeypot): un único perfil activo.

Seguridad:
- Todas las queries son parametrizadas (psycopg) → no hay SQL injection, ni siquiera
  con los payloads de ataque que el honeypot guarda verbatim.
- La config de perfiles se valida antes de persistir: tipos, rangos, y se rechazan
  CR/LF en headers (previene header/response splitting en las respuestas del honeypot).
- Respuestas con CSP estricta (script-src 'self') + nosniff + anti-clickjacking, de modo
  que un payload XSS capturado NO pueda ejecutarse al inspeccionarlo en el navegador.
Pensado para correr detrás de loopback; no tiene auth.
"""
import glob
import ipaddress
import os
import re
import secrets
import threading
import time
from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import unquote

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from flask import Flask, Response, jsonify, render_template, request

import report as report_mod  # generador de reportes (HTML oscuro / HTML A4 para Gotenberg)

WORDLIST_DIR = os.getenv("WORDLIST_DIR", "/wordlists")

app = Flask(__name__)

DSN = (
    f"host={os.getenv('DB_HOST', 'db')} "
    f"port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'honeypot')} "
    f"user={os.getenv('DB_USER', 'honeypot')} "
    f"password={os.getenv('DB_PASS', 'honeypot_dev_pass')}"
)

MAX_BODY_LEN = 1_000_000
MATCH_TYPES = {"exact", "prefix", "pattern"}


def connect():
    return psycopg.connect(DSN, row_factory=dict_row)


@app.after_request
def security_headers(resp):
    # Defensa en profundidad: aunque el escape del front falle, el navegador no
    # ejecuta scripts inyectados (no se permite inline script ni event handlers).
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# --------------------------------------------------------------------------- #
# Inspección de capturas (solo lectura)
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return render_template("index.html")


# Excluye IPs/rangos de la whitelist (infra propia) de los agregados "top",
# para que el monitor no domine el dashboard.
_EXCL = ("NOT EXISTS (SELECT 1 FROM ip_whitelist w "
         "WHERE requests.remote_addr <<= w.cidr)")


@app.route("/api/stats")
def stats():
    try:
        w = time_window()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    tfw, tp = w["tf"]("ts"), w["tp"]
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT count(*)                                 AS total,
                   count(DISTINCT remote_addr)              AS ips,
                   count(*) FILTER (WHERE body IS NOT NULL) AS con_body,
                   max(ts)                                  AS ultima
            FROM requests WHERE {tfw}
            """, tp)
        totals = cur.fetchone()
        cur.execute(
            "SELECT remote_addr::text AS remote_addr, count(*) AS hits "
            f"FROM requests WHERE {tfw} AND {_EXCL} GROUP BY remote_addr ORDER BY hits DESC LIMIT 10",
            tp)
        top_ips = cur.fetchall()
        cur.execute(
            f"SELECT path, count(*) AS hits FROM requests WHERE {tfw} AND {_EXCL} "
            "GROUP BY path ORDER BY hits DESC LIMIT 10", tp)
        top_paths = cur.fetchall()
        cur.execute(
            "SELECT coalesce(user_agent, '(sin UA)') AS user_agent, count(*) AS hits "
            f"FROM requests WHERE {tfw} AND {_EXCL} GROUP BY 1 ORDER BY hits DESC LIMIT 10", tp)
        top_uas = cur.fetchall()
        cur.execute(
            f"SELECT method, count(*) AS hits FROM requests WHERE {tfw} AND {_EXCL} "
            "GROUP BY method ORDER BY hits DESC", tp)
        methods = cur.fetchall()
    return jsonify(
        totals=totals, top_ips=top_ips, top_paths=top_paths,
        top_uas=top_uas, methods=methods,
    )


# Rango → (intervalo SQL o None=todo, bucket de la serie, etiqueta). Valores fijos
# del server (no entran del usuario) → seguros para interpolar en SQL.
ANALYTICS_RANGES = {
    "24h": ("24 hours", "hour", "24 h"),
    "48h": ("48 hours", "hour", "48 h"),
    "7d":  ("7 days",   "hour", "7 d"),
    "30d": ("30 days",  "day",  "30 d"),
    "90d": ("90 days",  "day",  "90 d"),
    "all": (None,       "day",  "todo"),
}


def time_window():
    """Ventana temporal global (usada por todos los tabs). Lee ?range= (preset) o
    ?from=&to= (custom). Devuelve dict con:
      tf(col) -> fragmento SQL de filtro para esa columna ts (usa %s en custom)
      tp      -> params del filtro (vacío en presets; [lo, hi] en custom)
      label, bucket, bounds (lo,hi)|None, win (interval|None), rng
    Las fechas custom SIEMPRE van por parámetro (nunca interpoladas). Lanza ValueError."""
    cfrom, cto = request.args.get("from"), request.args.get("to")
    if cfrom and cto:
        lo = datetime.fromisoformat(cfrom)
        hi = datetime.fromisoformat(cto)
        if len(cto) <= 10:                     # 'to' es fecha → incluir todo ese día
            hi = hi + timedelta(days=1)
        if hi <= lo:
            raise ValueError("'to' debe ser posterior a 'from'")
        bucket = "hour" if (hi - lo) <= timedelta(days=2) else "day"
        label = f"{lo.date()} → {(hi - timedelta(days=1)).date()}"
        return {"tf": (lambda col: f"{col} >= %s AND {col} < %s"), "tp": [lo, hi],
                "label": label, "bucket": bucket, "bounds": (lo, hi), "win": None, "rng": "custom"}
    rng = request.args.get("range", "24h")
    if rng not in ANALYTICS_RANGES:
        rng = "24h"
    win, bucket, label = ANALYTICS_RANGES[rng]
    return {"tf": (lambda col: f"{col} > now() - interval '{win}'" if win else "true"),
            "tp": [], "label": label, "bucket": bucket, "bounds": None, "win": win, "rng": rng}


@app.route("/api/analytics")
def analytics():
    """Agregados para el panel visual. Rango por preset (?range=24h|7d|30d|90d|all) o
    custom (?from=YYYY-MM-DD&to=YYYY-MM-DD). Excluye IPs de la whitelist (infra propia)."""
    excl_r = _EXCL.replace("requests.", "r.")
    try:
        w = time_window()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    tf, tp, label, bucket, bounds, rng = (w["tf"], w["tp"], w["label"],
                                          w["bucket"], w["bounds"], w["rng"])
    if bounds:
        start_expr = f"date_trunc('{bucket}', %s::timestamptz)"
        end_expr = f"date_trunc('{bucket}', %s::timestamptz)"
        series_params = list(bounds)
    else:
        win = w["win"]
        end_expr = f"date_trunc('{bucket}', now())"
        start_expr = (f"date_trunc('{bucket}', now() - interval '{win}')" if win else None)
        series_params = []

    step = "1 hour" if bucket == "hour" else "1 day"
    # start para 'all' (sin custom ni win): desde el primer dato de cada tabla
    start_req = start_expr or "(SELECT date_trunc('{b}', min(ts)) FROM requests)".format(b=bucket)
    start_alt = start_expr or "(SELECT date_trunc('{b}', min(ts)) FROM alerts)".format(b=bucket)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT count(*) AS total, "
            f"count(*) FILTER (WHERE {tf('ts')} AND {_EXCL}) AS inwin, "
            f"count(DISTINCT remote_addr) FILTER (WHERE {tf('ts')} AND {_EXCL}) AS ipswin "
            f"FROM requests", tp + tp)
        kpi = cur.fetchone()
        cur.execute(f"SELECT count(*) AS n FROM alerts WHERE {tf('ts')}", tp)
        alerts_win = cur.fetchone()["n"]
        cur.execute("SELECT coalesce(sum(trigger_count), 0) AS n FROM honeytokens")
        ht_trig = cur.fetchone()["n"]

        cur.execute(f"""
            WITH b AS (SELECT generate_series({start_req}, {end_expr}, interval '{step}') AS h)
            SELECT b.h AS t, count(r.id) AS n FROM b
            LEFT JOIN requests r ON date_trunc('{bucket}', r.ts) = b.h AND {excl_r}
            GROUP BY b.h ORDER BY b.h""", series_params)
        req_ts = cur.fetchall()
        cur.execute(f"""
            WITH b AS (SELECT generate_series({start_alt}, {end_expr}, interval '{step}') AS h)
            SELECT b.h AS t, count(a.id) AS n FROM b
            LEFT JOIN alerts a ON date_trunc('{bucket}', a.ts) = b.h
            GROUP BY b.h ORDER BY b.h""", series_params)
        alert_ts = cur.fetchall()

        # Breakdowns (misma ventana). severity SIEMPRE devuelve las 4 (aunque sean 0).
        cur.execute(f"SELECT severity, count(*) AS n FROM alerts WHERE {tf('ts')} GROUP BY severity", tp)
        sev = {r["severity"]: r["n"] for r in cur.fetchall()}
        severity = [{"severity": s, "n": sev.get(s, 0)}
                    for s in ("critical", "high", "medium", "low")]
        cur.execute(f"SELECT remote_addr::text AS k, count(*) AS n FROM requests r "
                    f"WHERE {tf('r.ts')} AND {excl_r} GROUP BY 1 ORDER BY n DESC LIMIT 10", tp)
        top_ips = cur.fetchall()
        cur.execute(f"SELECT path AS k, count(*) AS n FROM requests r "
                    f"WHERE {tf('r.ts')} AND {excl_r} GROUP BY 1 ORDER BY n DESC LIMIT 10", tp)
        top_paths = cur.fetchall()
        cur.execute(f"SELECT coalesce(nullif(method, ''), '(vacío)') AS k, count(*) AS n "
                    f"FROM requests r WHERE {tf('r.ts')} AND {excl_r} GROUP BY 1 ORDER BY n DESC LIMIT 8", tp)
        methods = cur.fetchall()
        cur.execute(f"SELECT (status/100)::text || 'xx' AS k, count(*) AS n FROM requests r "
                    f"WHERE status IS NOT NULL AND {tf('r.ts')} AND {excl_r} GROUP BY 1 ORDER BY 1", tp)
        status_classes = cur.fetchall()
        cur.execute(f"SELECT rule AS k, count(*) AS n FROM alerts "
                    f"WHERE {tf('ts')} AND rule NOT LIKE 'honeytoken%%' GROUP BY 1 ORDER BY n DESC LIMIT 10", tp)
        top_rules = cur.fetchall()
        cur.execute(f"SELECT coalesce(nullif(scheme, ''), '?') AS k, count(*) AS n "
                    f"FROM requests r WHERE {tf('r.ts')} AND {excl_r} GROUP BY 1 ORDER BY n DESC", tp)
        schemes = cur.fetchall()
        cur.execute(f"SELECT coalesce(nullif(user_agent, ''), '(sin UA)') AS k, count(*) AS n "
                    f"FROM requests r WHERE {tf('r.ts')} AND {excl_r} GROUP BY 1 ORDER BY n DESC LIMIT 8", tp)
        top_uas = cur.fetchall()

    def iso_ts(rows):
        return [{"t": r["t"].isoformat(), "n": r["n"]} for r in rows]

    return jsonify(
        range=rng, range_label=label, bucket=bucket,
        kpis={"total": kpi["total"], "inwin": kpi["inwin"], "ipswin": kpi["ipswin"],
              "alertswin": alerts_win, "honeytokens": ht_trig},
        requests_ts=iso_ts(req_ts), alerts_ts=iso_ts(alert_ts),
        severity=severity, top_ips=top_ips, top_paths=top_paths,
        methods=methods, status_classes=status_classes, top_rules=top_rules,
        schemes=schemes, top_uas=top_uas,
    )


@app.route("/api/requests")
def requests_list():
    try:
        w = time_window()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    q_ip = request.args.get("ip", "").strip()
    q_method = request.args.get("method", "").strip()
    q_search = request.args.get("q", "").strip()
    only_body = request.args.get("body") == "1"
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except ValueError:
        limit = 100
    try:
        before_id = int(request.args["before"]) if request.args.get("before") else None
    except ValueError:
        before_id = None

    where, params = [], []
    where.append(w["tf"]("ts"))
    params.extend(w["tp"])
    if q_ip:
        where.append("remote_addr = %s::inet")
        params.append(q_ip)
    if q_method:
        where.append("method = %s")
        params.append(q_method.upper())
    if only_body:
        where.append("body IS NOT NULL")
    if q_search:
        where.append("(uri ILIKE %s OR body ILIKE %s OR user_agent ILIKE %s)")
        like = f"%{q_search}%"
        params.extend([like, like, like])
    if before_id:
        where.append("id < %s")
        params.append(before_id)

    clause = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT id, ts, remote_addr::text AS remote_addr, scheme, method, status,
               uri, body_encoding, body_size, body_truncated, user_agent
        FROM requests {clause}
        ORDER BY id DESC LIMIT %s
    """
    params.append(limit)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    for r in rows:
        r["ts"] = r["ts"].isoformat() if r["ts"] else None
    return jsonify(rows=rows)


@app.route("/api/requests/<int:req_id>")
def request_detail(req_id):
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, ts, remote_addr::text AS remote_addr, remote_port, scheme, host,
                   method, uri, path, query, http_version, user_agent, headers,
                   raw_header, body, body_encoding, body_size, body_truncated,
                   status, request_time
            FROM requests WHERE id = %s
            """,
            (req_id,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify(error="not found"), 404
        # Alertas ya asociadas a esta request (automáticas y manuales), para que el
        # visor muestre si está clasificada y permita quitar las manuales.
        cur.execute(
            "SELECT id, ts, rule, severity, summary, "
            "(detail->>'source' = 'manual') AS manual "
            "FROM alerts WHERE request_id = %s ORDER BY id DESC",
            (req_id,),
        )
        alerts = cur.fetchall()
    row["ts"] = row["ts"].isoformat() if row["ts"] else None
    for a in alerts:
        a["ts"] = a["ts"].isoformat() if a["ts"] else None
    row["alerts"] = alerts
    return jsonify(row)


# --------------------------------------------------------------------------- #
# Perfiles / personas (lectura + escritura validada)
# --------------------------------------------------------------------------- #

class ValidationError(ValueError):
    pass


def _str(value, field, *, max_len, allow_empty=False):
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' debe ser texto")
    if not allow_empty and not value.strip():
        raise ValidationError(f"'{field}' no puede estar vacío")
    if len(value) > max_len:
        raise ValidationError(f"'{field}' excede {max_len} caracteres")
    return value


def _status(value, field):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"'{field}' debe ser un entero")
    if not 100 <= n <= 599:
        raise ValidationError(f"'{field}' debe ser un status HTTP (100-599)")
    return n


def _clean_header_value(value, field):
    # Rechaza CR/LF y bytes de control → evita header/response splitting cuando
    # el honeypot emita estos headers.
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' debe ser texto")
    if len(value) > 2048:
        raise ValidationError(f"'{field}' excede 2048 caracteres")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError(f"'{field}' contiene caracteres de control / saltos de línea")
    return value


# tchar de RFC 7230: letras, dígitos y estos símbolos. Sin espacios ni control
# (eso evita header-splitting), pero admite headers legítimos como 'atlassian.xsrf.token'.
_TCHAR_EXTRA = set("!#$%&'*+-.^_`|~")


def _header_name(name):
    if not isinstance(name, str) or not name:
        raise ValidationError("nombre de header inválido")
    if len(name) > 256:
        raise ValidationError("nombre de header demasiado largo")
    if not all(c.isalnum() or c in _TCHAR_EXTRA for c in name):
        raise ValidationError(f"nombre de header inválido: {name!r}")
    return name


def _headers_map(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"'{field}' debe ser un objeto {{header: valor}}")
    if len(value) > 50:
        raise ValidationError(f"'{field}' tiene demasiados headers")
    out = {}
    for k, v in value.items():
        out[_header_name(k)] = _clean_header_value(v, f"{field}[{k}]")
    return out


def _routes(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("'routes' debe ser una lista")
    if len(value) > 100:
        raise ValidationError("demasiadas rutas (máx 100)")
    out = []
    for i, r in enumerate(value):
        if not isinstance(r, dict):
            raise ValidationError(f"routes[{i}] debe ser un objeto")
        match_type = r.get("match_type", "prefix")
        if match_type not in MATCH_TYPES:
            raise ValidationError(f"routes[{i}].match_type inválido ({match_type})")
        out.append({
            "match": _str(r.get("match", ""), f"routes[{i}].match", max_len=1024),
            "match_type": match_type,
            "status": _status(r.get("status", 200), f"routes[{i}].status"),
            "content_type": _clean_header_value(
                r.get("content_type", "text/html"), f"routes[{i}].content_type"),
            "headers": _headers_map(r.get("headers"), f"routes[{i}].headers"),
            "body": _str(r.get("body", ""), f"routes[{i}].body",
                         max_len=MAX_BODY_LEN, allow_empty=True),
        })
    return out


def validate_profile(data, *, require_name=True):
    if not isinstance(data, dict):
        raise ValidationError("payload inválido")
    out = {}
    if require_name or "name" in data:
        name = _str(data.get("name", ""), "name", max_len=100)
        if not all(c.isalnum() or c in "-_." for c in name):
            raise ValidationError("'name' solo admite letras, dígitos, '-', '_' y '.'")
        out["name"] = name
    out["server_header"] = _clean_header_value(
        data.get("server_header", "Apache/2.4.41 (Ubuntu)"), "server_header")
    out["index_status"] = _status(data.get("index_status", 200), "index_status")
    out["index_body"] = _str(data.get("index_body", ""), "index_body",
                             max_len=MAX_BODY_LEN, allow_empty=True)
    out["notfound_status"] = _status(data.get("notfound_status", 404), "notfound_status")
    out["notfound_body"] = _str(data.get("notfound_body", ""), "notfound_body",
                                max_len=MAX_BODY_LEN, allow_empty=True)
    out["extra_headers"] = _headers_map(data.get("extra_headers"), "extra_headers")
    out["routes"] = _routes(data.get("routes"))
    return out


@app.errorhandler(ValidationError)
def _handle_validation(err):
    return jsonify(error=str(err)), 400


@app.route("/api/profiles")
def profiles_list():
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, name, server_header, is_active, updated_at, "
            "jsonb_array_length(routes) AS n_routes "
            "FROM profiles ORDER BY id"
        )
        rows = cur.fetchall()
    for r in rows:
        r["updated_at"] = r["updated_at"].isoformat() if r["updated_at"] else None
    return jsonify(rows=rows)


@app.route("/api/profiles/<int:pid>")
def profile_get(pid):
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, name, server_header, index_status, index_body, "
            "notfound_status, notfound_body, extra_headers, routes, is_active, updated_at "
            "FROM profiles WHERE id = %s",
            (pid,),
        )
        row = cur.fetchone()
    if not row:
        return jsonify(error="not found"), 404
    row["updated_at"] = row["updated_at"].isoformat() if row["updated_at"] else None
    return jsonify(row)


@app.route("/api/profiles", methods=["POST"])
def profile_create():
    data = validate_profile(request.get_json(force=True, silent=True) or {})
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO profiles
                (name, server_header, index_status, index_body,
                 notfound_status, notfound_body, extra_headers, routes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (data["name"], data["server_header"], data["index_status"],
             data["index_body"], data["notfound_status"], data["notfound_body"],
             Jsonb(data["extra_headers"]), Jsonb(data["routes"])),
        )
        new_id = cur.fetchone()["id"]
        conn.commit()
    return jsonify(id=new_id), 201


@app.route("/api/profiles/<int:pid>", methods=["PUT"])
def profile_update(pid):
    data = validate_profile(request.get_json(force=True, silent=True) or {},
                            require_name=False)
    sets = ["server_header = %s", "index_status = %s", "index_body = %s",
            "notfound_status = %s", "notfound_body = %s",
            "extra_headers = %s", "routes = %s", "updated_at = now()"]
    params = [data["server_header"], data["index_status"], data["index_body"],
              data["notfound_status"], data["notfound_body"],
              Jsonb(data["extra_headers"]), Jsonb(data["routes"])]
    if "name" in data:
        sets.insert(0, "name = %s")
        params.insert(0, data["name"])
    params.append(pid)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(f"UPDATE profiles SET {', '.join(sets)} WHERE id = %s", params)
        updated = cur.rowcount
        conn.commit()
    if not updated:
        return jsonify(error="not found"), 404
    return jsonify(ok=True)


@app.route("/api/profiles/<int:pid>", methods=["DELETE"])
def profile_delete(pid):
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT is_active FROM profiles WHERE id = %s", (pid,))
        row = cur.fetchone()
        if not row:
            return jsonify(error="not found"), 404
        if row["is_active"]:
            return jsonify(error="no se puede borrar el perfil activo"), 409
        cur.execute("DELETE FROM profiles WHERE id = %s", (pid,))
        conn.commit()
    return jsonify(ok=True)


@app.route("/api/profiles/<int:pid>/activate", methods=["POST"])
def profile_activate(pid):
    # Un solo perfil activo: desactivamos todos y activamos el pedido, en una
    # transacción (el índice único parcial garantiza la invariante igual).
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM profiles WHERE id = %s", (pid,))
        if not cur.fetchone():
            return jsonify(error="not found"), 404
        cur.execute("UPDATE profiles SET is_active = false WHERE is_active")
        cur.execute("UPDATE profiles SET is_active = true WHERE id = %s", (pid,))
        conn.commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------------- #
# Alertas (solo lectura) + honeytokens (lectura + alta/baja validada)
# --------------------------------------------------------------------------- #

HONEYTOKEN_KINDS = {"canary_path", "api_key", "credential", "custom"}


ALERT_SEVERITIES = ("critical", "high", "medium", "low", "info")


@app.route("/api/requests/<int:req_id>/alert", methods=["POST"])
def alert_mark(req_id):
    """Clasificación manual: marca una request como alerta (rule='manual').

    Complementa al watcher automático para los casos que no matchean ninguna regla.
    Se marca con detail.source='manual' y notified=true (el humano ya la vio → no
    se reenvía a ningún webhook; el watcher nunca re-escanea esta tabla).
    """
    data = request.get_json(force=True, silent=True) or {}
    sev = str(data.get("severity", "medium")).strip().lower()
    if sev not in ALERT_SEVERITIES:
        raise ValidationError(f"severity inválida (usá una de {list(ALERT_SEVERITIES)})")
    note = str(data.get("note", "")).strip()[:500]
    summary = ("manual: " + note) if note else "Clasificada manualmente"
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT remote_addr FROM requests WHERE id = %s", (req_id,))
        req = cur.fetchone()
        if not req:
            return jsonify(error="request no encontrada"), 404
        cur.execute(
            "INSERT INTO alerts (request_id, rule, severity, remote_addr, summary, "
            "detail, notified) VALUES (%s, 'manual', %s, %s, %s, %s, true) "
            "RETURNING id, ts",
            (req_id, sev, req["remote_addr"], summary,
             Jsonb({"source": "manual", "note": note})),
        )
        row = cur.fetchone()
        conn.commit()
    return jsonify(id=row["id"], ts=row["ts"].isoformat(), rule="manual",
                   severity=sev, summary=summary, manual=True), 201


@app.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
def alert_delete(alert_id):
    """Quita una alerta MANUAL (no toca las automáticas del watcher)."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM alerts WHERE id = %s AND detail->>'source' = 'manual'",
            (alert_id,))
        deleted = cur.rowcount
        conn.commit()
    if not deleted:
        return jsonify(error="no existe o no es una alerta manual"), 404
    return jsonify(ok=True)


@app.route("/api/alerts")
def alerts_list():
    try:
        w = time_window()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    sevs = [s.strip().lower() for s in request.args.get("severity", "").split(",") if s.strip()]
    rules = [s.strip() for s in request.args.get("rule", "").split(",") if s.strip()]
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except ValueError:
        limit = 100
    try:
        before = int(request.args["before"]) if request.args.get("before") else None
    except ValueError:
        before = None
    where, params = [], []
    where.append(w["tf"]("a.ts"))
    params.extend(w["tp"])
    if sevs:
        where.append("a.severity = ANY(%s)")
        params.append(sevs)
    if rules:
        where.append("a.rule = ANY(%s)")
        params.append(rules)
    if before:
        where.append("a.id < %s")
        params.append(before)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT a.id, a.ts, a.request_id, a.rule, a.severity, "
            f"a.remote_addr::text AS remote_addr, a.summary, a.detail, a.notified, "
            f"r.body_size, r.body_encoding "
            f"FROM alerts a LEFT JOIN requests r ON r.id = a.request_id "
            f"{clause} ORDER BY a.id DESC LIMIT %s", params)
        rows = cur.fetchall()
    for r in rows:
        r["ts"] = r["ts"].isoformat() if r["ts"] else None
    return jsonify(rows=rows)


@app.route("/api/alerts/stats")
def alerts_stats():
    try:
        w = time_window()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    tfw, tp, label = w["tf"]("ts"), w["tp"], w["label"]
    with connect() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT severity, count(*) AS n FROM alerts WHERE {tfw} GROUP BY severity", tp)
        bys = {r["severity"]: r["n"] for r in cur.fetchall()}
        by_sev = {s: bys.get(s, 0) for s in ("critical", "high", "medium", "low")}
        cur.execute(f"SELECT rule, count(*) AS n FROM alerts WHERE {tfw} GROUP BY rule "
                    "ORDER BY n DESC LIMIT 10", tp)
        by_rule = cur.fetchall()
        cur.execute(f"SELECT count(*) AS n FROM alerts WHERE {tfw}", tp)
        inwin = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM alerts")
        total = cur.fetchone()["n"]
        cur.execute("SELECT DISTINCT rule FROM alerts ORDER BY rule")
        all_rules = [r["rule"] for r in cur.fetchall()]
    return jsonify(by_severity=by_sev, by_rule=by_rule, inwin=inwin, total=total,
                   range_label=label, rules=all_rules)


@app.route("/api/honeytokens")
def honeytokens_list():
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, token, kind, description, active, trigger_count, "
            "first_triggered, last_triggered, created_at FROM honeytokens ORDER BY id")
        rows = cur.fetchall()
    for r in rows:
        for k in ("first_triggered", "last_triggered", "created_at"):
            r[k] = r[k].isoformat() if r[k] else None
    return jsonify(rows=rows)


def _gen_token(kind):
    """Genera un honeytoken fresco y aleatorio según el tipo (cada llamada es único)."""
    if kind == "canary_path":
        return "/backup/" + secrets.token_hex(8) + ".sql.gz"
    if kind == "api_key":
        return "AKIA" + secrets.token_hex(8).upper()
    if kind == "credential":
        return "svc_" + secrets.token_hex(6) + ":" + secrets.token_hex(8)
    return secrets.token_hex(16)


@app.route("/api/honeytokens", methods=["POST"])
def honeytoken_create():
    data = request.get_json(force=True, silent=True) or {}
    kind = str(data.get("kind", "custom")).strip()
    if kind not in HONEYTOKEN_KINDS:
        raise ValidationError(f"kind inválido (usá uno de {sorted(HONEYTOKEN_KINDS)})")
    token = str(data.get("token", "")).strip()
    if not token:
        token = _gen_token(kind)  # autogeneración según el tipo
    if len(token) > 512:
        raise ValidationError("token demasiado largo")
    desc = str(data.get("description", ""))[:1000]
    with connect() as conn, conn.cursor() as cur:
        try:
            cur.execute(
                "INSERT INTO honeytokens (token, kind, description) VALUES (%s,%s,%s) "
                "RETURNING id, token", (token, kind, desc))
        except psycopg.errors.UniqueViolation:
            conn.rollback()
            return jsonify(error="ese token ya existe"), 409
        row = cur.fetchone()
        conn.commit()
    return jsonify(id=row["id"], token=row["token"]), 201


@app.route("/api/honeytokens/<int:hid>/rotate", methods=["POST"])
def honeytoken_rotate(hid):
    """Rota un honeytoken: nuevo valor aleatorio del mismo tipo y resetea los contadores
    (trigger_count / first / last). El canario viejo deja de ser válido. Reintenta ante
    colisión improbable de valores."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT kind FROM honeytokens WHERE id = %s", (hid,))
        row = cur.fetchone()
        if not row:
            return jsonify(error="not found"), 404
        kind = row["kind"]
        for _ in range(5):
            try:
                cur.execute(
                    "UPDATE honeytokens SET token = %s, trigger_count = 0, "
                    "first_triggered = NULL, last_triggered = NULL "
                    "WHERE id = %s RETURNING token", (_gen_token(kind), hid))
                new = cur.fetchone()
                conn.commit()
                return jsonify(id=hid, token=new["token"])
            except psycopg.errors.UniqueViolation:
                conn.rollback()
    return jsonify(error="no se pudo generar un valor único, reintentá"), 409


@app.route("/api/honeytokens/<int:hid>", methods=["DELETE"])
def honeytoken_delete(hid):
    with connect() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM honeytokens WHERE id = %s", (hid,))
        deleted = cur.rowcount
        conn.commit()
    if not deleted:
        return jsonify(error="not found"), 404
    return jsonify(ok=True)


# --------------------------------------------------------------------------- #
# Whitelist de IPs propias (infra nuestra a ignorar)
# --------------------------------------------------------------------------- #

@app.route("/api/whitelist")
def whitelist_list():
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, cidr::text AS cidr, note, created_at "
                    "FROM ip_whitelist ORDER BY id")
        rows = cur.fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
    return jsonify(rows=rows)


@app.route("/api/whitelist", methods=["POST"])
def whitelist_create():
    data = request.get_json(force=True, silent=True) or {}
    raw = str(data.get("cidr", "")).strip()
    if not raw:
        raise ValidationError("falta 'cidr' (IP o rango, ej. 1.2.3.4 o 1.2.3.0/24)")
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise ValidationError(f"IP/CIDR inválido: {raw!r}")
    note = str(data.get("note", ""))[:500]
    with connect() as conn, conn.cursor() as cur:
        try:
            cur.execute("INSERT INTO ip_whitelist (cidr, note) VALUES (%s, %s) RETURNING id",
                        (str(net), note))
        except psycopg.errors.UniqueViolation:
            conn.rollback()
            return jsonify(error="esa IP/rango ya está en la whitelist"), 409
        new_id = cur.fetchone()["id"]
        conn.commit()
    return jsonify(id=new_id, cidr=str(net)), 201


@app.route("/api/whitelist/<int:wid>", methods=["DELETE"])
def whitelist_delete(wid):
    with connect() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM ip_whitelist WHERE id = %s", (wid,))
        deleted = cur.rowcount
        conn.commit()
    if not deleted:
        return jsonify(error="not found"), 404
    return jsonify(ok=True)


# --------------------------------------------------------------------------- #
# Wordlist de vectores (diccionario de paths capturados) — on-demand + snapshot diario
# --------------------------------------------------------------------------- #

# Defang: el diccionario se PUBLICA (GitHub) y se PROPAGA (NFS). Los vectores crudos
# traen infraestructura de malware viva (C2/hosts de droppers como Mozi) y comandos
# destructivos. Antes de generar/propagar se neutralizan, preservando la firma del vector:
#   - IP pública  -> 127.0.0.1   (no re-hospedamos/amplificamos el C2 del atacante)
#   - rm -rf ...  -> defanged     (no distribuimos un comando destructivo ejecutable)
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
# comandos destructivos (separador = espacio, '+' o %20 por url-encoding)
_DANGER_RE = [
    (re.compile(r"\brm(?:\+|%20|\s|/)+-[rf]{1,2}f?\b", re.I), "rm_DEFANGED"),
]


def _ip_to_local(m):
    try:
        if ipaddress.ip_address(m.group(0)).is_global:   # pública (no priv/loopback/reservada)
            return "127.0.0.1"
    except ValueError:
        pass
    return m.group(0)


def defang(entry):
    """Neutraliza una entrada del diccionario antes de publicarla/propagarla."""
    entry = _IPV4_RE.sub(_ip_to_local, entry)
    for rx, rep in _DANGER_RE:
        entry = rx.sub(rep, entry)
    return entry


# Shell-safe: reemplaza TODO lo que no sea de un allowlist seguro por '_'. Deja afuera
# espacios, saltos de línea, y todos los metacaracteres de shell/glob
# (;  |  &  $  ( )  `  < >  \  ' "  { }  * ?  [ ]  ~  !  #  ^ ...). El resultado es inofensivo
# aunque se interpole SIN comillas en un shell; pierde fidelidad pero el vector sigue legible.
# Pensado para consumir el diccionario directo en pipelines (ej. scannerOSCP) sin riesgo de
# inyección de comandos. El allowlist (. / - _ + % = : @ ,) es seguro unquoted.
_SHELL_UNSAFE_RE = re.compile(r"[^A-Za-z0-9./\-_+%=:@,]")


def shell_safe(entry):
    return _SHELL_UNSAFE_RE.sub("_", entry)


def generate_wordlist(cur, tfw, tp, mode="paths", min_count=1, top=None,
                      strip_slash=True, decode=False):
    """Genera el wordlist desde las requests capturadas (crudas). Excluye whitelist. Modos:
      paths    = path sin query            files = nombre de archivo
      segments = segmentos del path        uris  = URI COMPLETA (path + query = el vector crudo,
                                                   preserva el payload del ataque)."""
    cur.execute(
        f"SELECT uri, count(*) AS n FROM requests "
        f"WHERE uri <> '' AND {tfw} AND {_EXCL} GROUP BY 1", tp)
    rows = cur.fetchall()
    counts = Counter()
    for r in rows:
        uri, n = r["uri"], r["n"]
        if not uri:
            continue
        path = uri.split("?", 1)[0]
        if decode:
            uri = unquote(uri)
            path = unquote(path)
        uri = defang(uri)    # neutraliza IPs públicas (C2) y comandos destructivos
        path = defang(path)  # antes de que la entrada entre al diccionario
        if mode == "uris":
            entry = uri.lstrip("/") if strip_slash else uri
            if entry:
                counts[entry] += n
        elif mode == "uris-safe":
            entry = shell_safe(uri.lstrip("/") if strip_slash else uri)
            if entry:
                counts[entry] += n
        elif mode == "paths":
            entry = path.lstrip("/") if strip_slash else path
            if entry:
                counts[entry] += n
        elif mode == "files":
            leaf = path.rstrip("/").rsplit("/", 1)[-1]
            if leaf:
                counts[leaf] += n
        elif mode == "segments":
            for seg in path.split("/"):
                if seg:
                    counts[seg] += n
    items = [(e, c) for e, c in counts.items() if c >= min_count]
    items.sort(key=lambda x: (-x[1], x[0]))
    if top:
        items = items[:top]
    return items


@app.route("/api/report")
def api_report():
    """Reporte de actividad (loopback). `style=pdf` → HTML A4 estilo pentest (para
    Gotenberg); `style=web` → HTML oscuro. `scope=public` recorta para publicación."""
    scope = request.args.get("scope", "private")
    if scope not in ("private", "public"):
        scope = "private"
    style = request.args.get("style", "pdf")
    try:
        hours = min(max(int(request.args.get("hours", 24)), 1), 24 * 30)
    except ValueError:
        hours = 24
    data = report_mod.gather(hours)
    renderer = report_mod.render_pdf if style == "pdf" else report_mod.render
    return Response(renderer(data, scope=scope), mimetype="text/html; charset=utf-8")


@app.route("/api/wordlist")
def wordlist_download():
    """Descarga on-demand del wordlist (siempre fresco), con parámetros."""
    try:
        w = time_window()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    mode = request.args.get("mode", "paths")
    if mode not in ("paths", "files", "segments", "uris", "uris-safe"):
        mode = "paths"
    try:
        min_count = max(1, int(request.args.get("min_count", 1)))
    except ValueError:
        min_count = 1
    try:
        top = int(request.args["top"]) if request.args.get("top") else None
    except ValueError:
        top = None
    strip_slash = request.args.get("strip_slash", "1") != "0"
    decode = request.args.get("decode") == "1"
    with_count = request.args.get("with_count") == "1"
    with connect() as conn, conn.cursor() as cur:
        items = generate_wordlist(cur, w["tf"]("ts"), w["tp"], mode, min_count,
                                  top, strip_slash, decode)
    body = "".join((f"{c}\t{e}\n" if with_count else e + "\n") for e, c in items)
    fname = f"wordlist-{mode}.txt"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _snapshot_files():
    out = []
    for f in sorted(glob.glob(os.path.join(WORDLIST_DIR, "wordlist-*.txt")), reverse=True):
        try:
            st = os.stat(f)
            with open(f, encoding="utf-8") as fh:
                lines = sum(1 for _ in fh)
            out.append({"name": os.path.basename(f), "bytes": st.st_size, "lines": lines})
        except OSError:
            pass
    return out


@app.route("/api/wordlists")
def wordlists_list():
    return jsonify(rows=_snapshot_files())


@app.route("/api/wordlists/<name>")
def wordlist_snapshot(name):
    # solo nombres con el patrón exacto → evita path traversal
    if not re.fullmatch(r"wordlist-\d{4}-\d{2}-\d{2}\.txt", name):
        return jsonify(error="nombre inválido"), 400
    path = os.path.join(WORDLIST_DIR, name)
    if not os.path.isfile(path):
        return jsonify(error="not found"), 404
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _write_daily_snapshot():
    """Genera el snapshot del día (si no existe) con parámetros por default."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(WORDLIST_DIR, f"wordlist-{today}.txt")
    if os.path.exists(path):
        return
    with connect() as conn, conn.cursor() as cur:
        items = generate_wordlist(cur, "true", [], mode="paths", min_count=2,
                                  strip_slash=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("".join(e + "\n" for e, _ in items))
    os.replace(tmp, path)


def _snapshot_worker():
    while True:
        try:
            _write_daily_snapshot()
        except Exception as e:  # noqa: BLE001
            print(f"wordlist snapshot error: {e}", flush=True)
        time.sleep(3600)  # revisa cada hora; escribe uno por día


# Arranca el generador de snapshots diarios en un hilo daemon (una sola vez).
threading.Thread(target=_snapshot_worker, daemon=True).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
