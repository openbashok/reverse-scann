#!/usr/bin/env python3
"""alerter — vigila la tabla `requests` del honeypot y genera alertas.

Cada N segundos lee los requests nuevos (id > último procesado) y por cada uno:
  1. busca honeytokens activos en uri/body/headers → alerta `honeytoken` (critical)
  2. aplica un ruleset de alto valor (traversal, RCE, SQLi, log4shell, webshells,
     paths de recon conocidos) → alerta con severidad
Escribe todo en `alerts` y, si hay ALERT_WEBHOOK_URL, dispara webhook (Slack/Discord/
genérico) para las alertas de severidad >= ALERT_MIN_SEVERITY, con throttle por (ip, regla).

Desacoplado del honeypot: solo lee `requests`, no toca el hot-path de captura.
"""
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request

import psycopg
from psycopg.rows import dict_row

POLL_INTERVAL = float(os.getenv("ALERT_POLL_INTERVAL", "5"))
WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "high").lower()
BATCH = int(os.getenv("ALERT_BATCH", "500"))
THROTTLE_SECONDS = int(os.getenv("ALERT_THROTTLE", "3600"))

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DSN = (
    f"host={os.getenv('DB_HOST', 'db')} port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'honeypot')} user={os.getenv('DB_USER', 'honeypot')} "
    f"password={os.getenv('DB_PASS', 'honeypot_dev_pass')}"
)

# Ruleset de alto valor. Cada regla: (nombre, severidad, dónde, regex).
# 'where': uri | body | any (uri+body+headers). Case-insensitive.
RULES = [
    ("log4shell",        "critical", "any",  r"\$\{jndi:(ldap|rmi|dns|ldaps|iiop)"),
    ("rce_cmd_injection","high",     "any",  r"(;|\||`|\$\()\s*(cat|wget|curl|bash|sh|nc|ncat|python|perl|id|uname|whoami)\b"),
    ("rce_spring_ognl",  "high",     "any",  r"\$\{.*(getRuntime|ProcessBuilder|T\(java)"),
    ("webshell_php",     "high",     "any",  r"(eval|assert|system|passthru|shell_exec|base64_decode)\s*\("),
    ("file_read_passwd", "medium",   "any",  r"/etc/(passwd|shadow)\b"),
    ("path_traversal",   "medium",   "any",  r"(\.\./|\.\.%2f|%2e%2e%2f|\.\.\\|%252e%252e)"),
    ("sqli",             "medium",   "any",  r"(union\s+select|\bor\s+1\s*=\s*1\b|sleep\(\s*\d|benchmark\(|information_schema|' or '1'='1)"),
    ("xss",              "low",      "any",  r"(<script|onerror\s*=|javascript:)"),
    ("recon_sensitive",  "low",      "uri",  r"(/\.env|/\.git/|/wp-login\.php|/xmlrpc\.php|/actuator|/boaform|/solr/|/\.aws/|/phpmyadmin|/jenkins|/\.ssh/)"),
]
COMPILED = [(n, s, w, re.compile(p, re.IGNORECASE)) for (n, s, w, p) in RULES]


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def connect():
    return psycopg.connect(DSN, row_factory=dict_row, autocommit=True)


def decoded_body(req):
    body, enc = req.get("body"), req.get("body_encoding")
    if not body:
        return ""
    if enc == "base64":
        try:
            return base64.b64decode(body).decode("utf-8", "replace")
        except Exception:
            return body
    return body


def load_whitelist(cur):
    """Devuelve lista de ip_network de la tabla ip_whitelist (vacía si no existe)."""
    try:
        cur.execute("SELECT cidr::text AS cidr FROM ip_whitelist")
        nets = []
        for r in cur.fetchall():
            try:
                nets.append(ipaddress.ip_network(r["cidr"], strict=False))
            except ValueError:
                pass
        return nets
    except Exception:
        return []


def is_whitelisted(addr, nets):
    if not addr or not nets:
        return False
    try:
        ip = ipaddress.ip_address(addr.split("/")[0])
    except ValueError:
        return False
    return any(ip in n for n in nets)


def haystacks(req):
    uri = req.get("uri") or ""
    body = decoded_body(req)
    headers = json.dumps(req.get("headers") or {}, default=str)
    return uri, body, (uri + "\n" + body + "\n" + headers)


def evaluate(req, tokens):
    """Devuelve lista de alertas (dicts) para un request."""
    uri, body, allhay = haystacks(req)
    alerts = []

    # 1) honeytokens
    for tok in tokens:
        if tok["token"] and tok["token"] in allhay:
            alerts.append({
                "rule": f"honeytoken:{tok['kind']}",
                "severity": "critical",
                "summary": f"Honeytoken reutilizado ({tok['kind']}): {tok['token'][:60]}",
                "detail": {"honeytoken_id": tok["id"], "kind": tok["kind"],
                           "token": tok["token"]},
                "_token_id": tok["id"],
            })

    # 2) ruleset
    for name, sev, where, rx in COMPILED:
        hay = uri if where == "uri" else (body if where == "body" else allhay)
        m = rx.search(hay)
        if m:
            alerts.append({
                "rule": name, "severity": sev,
                "summary": f"{name}: {m.group(0)[:80]}",
                "detail": {"match": m.group(0)[:200], "where": where},
            })
    return alerts


def send_webhook(alert, req):
    if not WEBHOOK_URL:
        return False
    if SEV_ORDER.get(alert["severity"], 0) < SEV_ORDER.get(MIN_SEVERITY, 3):
        return False
    text = (f"🚨 [{alert['severity'].upper()}] {alert['rule']}\n"
            f"{alert['summary']}\n"
            f"IP: {req.get('remote_addr')}  ·  {req.get('method')} {(req.get('uri') or '')[:120]}\n"
            f"request_id={req.get('id')}")
    payload = json.dumps({"text": text, "content": text,
                          "alert": {k: alert[k] for k in ("rule", "severity", "summary")}}).encode()
    try:
        r = urllib.request.Request(WEBHOOK_URL, data=payload,
                                   headers={"Content-Type": "application/json"})
        urllib.request.urlopen(r, timeout=8).read()
        return True
    except Exception as e:
        log(f"webhook error: {e}")
        return False


def main():
    log(f"alerter arrancando. poll={POLL_INTERVAL}s webhook={'sí' if WEBHOOK_URL else 'no'} "
        f"min_sev={MIN_SEVERITY}")
    throttle = {}  # (ip, rule) -> last_notified_epoch  (throttle solo del webhook)
    # reloj monotónico simulado con contador de ticks (no usamos time real para throttle fino)
    while True:
        try:
            with connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT last_request_id FROM alerter_state WHERE id = 1")
                row = cur.fetchone()
                last_id = row["last_request_id"] if row else 0

                cur.execute(
                    "SELECT id, ts, remote_addr::text AS remote_addr, method, uri, "
                    "headers, body, body_encoding FROM requests "
                    "WHERE id > %s ORDER BY id ASC LIMIT %s", (last_id, BATCH))
                reqs = cur.fetchall()

                if reqs:
                    cur.execute("SELECT id, token, kind FROM honeytokens WHERE active")
                    tokens = cur.fetchall()
                    whitelist = load_whitelist(cur)
                    now = time.time()
                    n_alerts = 0
                    for req in reqs:
                        if is_whitelisted(req.get("remote_addr"), whitelist):
                            continue  # IP propia: avanza last_id pero no genera alertas
                        for al in evaluate(req, tokens):
                            key = (req.get("remote_addr"), al["rule"])
                            do_notify = (now - throttle.get(key, 0)) >= THROTTLE_SECONDS
                            notified = send_webhook(al, req) if do_notify else False
                            if notified:
                                throttle[key] = now
                            cur.execute(
                                "INSERT INTO alerts (request_id, rule, severity, remote_addr, "
                                "summary, detail, notified) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                                (req["id"], al["rule"], al["severity"], req["remote_addr"],
                                 al["summary"], psycopg.types.json.Jsonb(al["detail"]), notified))
                            if "_token_id" in al:
                                cur.execute(
                                    "UPDATE honeytokens SET trigger_count = trigger_count + 1, "
                                    "last_triggered = now(), "
                                    "first_triggered = coalesce(first_triggered, now()) "
                                    "WHERE id = %s", (al["_token_id"],))
                            n_alerts += 1
                    cur.execute("UPDATE alerter_state SET last_request_id = %s WHERE id = 1",
                                (reqs[-1]["id"],))
                    if n_alerts:
                        log(f"procesados {len(reqs)} requests, {n_alerts} alertas")
        except Exception as e:
            log(f"loop error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
