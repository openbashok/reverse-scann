#!/usr/bin/env python3
"""Generador de reportes del honeypot reverse-scann.

Produce un HTML **autocontenido** (sin assets externos) con los números y gráficos
del período: KPIs con tendencia, actividad en el tiempo, métodos, status, severidad
de alertas, top paths/IPs/user-agents, nuevos vectores y tendencia a 14 días.

Decisiones de diseño:
- Gráficos en **HTML/CSS** (barras con ancho %) en vez de SVG: Gmail descarta los SVG
  de los mails, pero renderiza divs con color y ancho perfecto. Así el MISMO HTML sirve
  para el mail y para la web.
- **Todo valor dinámico se escapa** con html.escape() (los paths/UA son texto de atacante;
  acá los mostramos como texto, nunca como markup) → no hay XSS ni en el mail ni en la web.
- Dos scopes: `private` (todo) y `public` (agregados; sin identidad del honeypot ni bodies)
  para publicar en GitHub Pages sin quemar la caja.

Uso:
    python3 report.py --scope private --hours 24 --out /tmp/report.html
    python3 report.py --scope public  --hours 24 --out /tmp/report-public.html

Conexión: variables DB_* (igual que el dashboard).
"""
import argparse
import html
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row

DSN = (
    f"host={os.getenv('DB_HOST', 'db')} "
    f"port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'honeypot')} "
    f"user={os.getenv('DB_USER', 'honeypot')} "
    f"password={os.getenv('DB_PASS', 'honeypot_dev_pass')}"
)

# Excluye infra propia (igual criterio que el dashboard).
_EXCL = ("NOT EXISTS (SELECT 1 FROM ip_whitelist w "
         "WHERE requests.remote_addr <<= w.cidr)")

# --- Paleta (branding OpenBash + categóricos validados del skill dataviz) ------
BRAND_MAGENTA = "#bf0d57"
BRAND_NAVY = "#2a2759"
BRAND_ACCENT = "#00ff85"
INK = "#d6deeb"
DIM = "#7e8aa0"
BG = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1c2230"
BORDER = "#2b3242"
CAT = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181",
       "#9085e9", "#008300", "#e66767"]
SEVC = {"critical": "#e66767", "high": "#d95926", "medium": "#c98500",
        "low": "#3987e5", "info": "#7e8aa0"}


# --------------------------------------------------------------------------- #
# Consultas
# --------------------------------------------------------------------------- #

def _fetch(cur, sql, params=None):
    cur.execute(sql, params or [])
    return cur.fetchall()


def gather(hours):
    """Junta todas las métricas del período (y las comparaciones de tendencia)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    prev_start = now - timedelta(hours=hours * 2)
    d = {"now": now, "start": start, "hours": hours}

    with psycopg.connect(DSN, row_factory=dict_row) as conn, conn.cursor() as cur:
        # KPIs del período actual vs el período anterior (misma duración).
        def kpis(a, b):
            row = _fetch(cur, f"""
                SELECT count(*) AS reqs,
                       count(DISTINCT remote_addr) AS ips,
                       count(*) FILTER (WHERE body_size > 0) AS withbody
                FROM requests
                WHERE ts >= %s AND ts < %s AND {_EXCL}""", [a, b])[0]
            al = _fetch(cur, "SELECT count(*) AS n FROM alerts WHERE ts >= %s AND ts < %s",
                        [a, b])[0]["n"]
            return {"reqs": row["reqs"], "ips": row["ips"],
                    "withbody": row["withbody"], "alerts": al}

        d["cur"] = kpis(start, now)
        d["prev"] = kpis(prev_start, start)

        # Honeytokens disparados en el período.
        d["ht_trig"] = _fetch(cur, """
            SELECT count(*) AS n FROM alerts
            WHERE ts >= %s AND rule LIKE 'honeytoken%%'""", [start])[0]["n"]

        # Serie por hora (período).
        d["hourly"] = _fetch(cur, f"""
            SELECT date_trunc('hour', ts) AS h, count(*) AS n
            FROM requests WHERE ts >= %s AND {_EXCL}
            GROUP BY h ORDER BY h""", [start])

        # Tendencia a 14 días: requests y alertas por día.
        d14 = now - timedelta(days=14)
        d["daily_reqs"] = _fetch(cur, f"""
            SELECT date_trunc('day', ts) AS d, count(*) AS n
            FROM requests WHERE ts >= %s AND {_EXCL}
            GROUP BY d ORDER BY d""", [d14])
        d["daily_alerts"] = _fetch(cur, """
            SELECT date_trunc('day', ts) AS d, count(*) AS n
            FROM alerts WHERE ts >= %s GROUP BY d ORDER BY d""", [d14])

        # Breakdowns del período.
        d["methods"] = _fetch(cur, f"""
            SELECT coalesce(nullif(method, ''), '(vacío)') AS k, count(*) AS n
            FROM requests WHERE ts >= %s AND {_EXCL}
            GROUP BY k ORDER BY n DESC LIMIT 8""", [start])
        d["status"] = _fetch(cur, f"""
            SELECT coalesce(status::text, '?') AS k, count(*) AS n
            FROM requests WHERE ts >= %s AND {_EXCL}
            GROUP BY k ORDER BY n DESC LIMIT 8""", [start])
        d["paths"] = _fetch(cur, f"""
            SELECT coalesce(nullif(path, ''), '(vacío)') AS k, count(*) AS n
            FROM requests WHERE ts >= %s AND path IS NOT NULL AND {_EXCL}
            GROUP BY k ORDER BY n DESC LIMIT 15""", [start])
        d["ips"] = _fetch(cur, f"""
            SELECT remote_addr::text AS k, count(*) AS n
            FROM requests WHERE ts >= %s AND {_EXCL}
            GROUP BY k ORDER BY n DESC LIMIT 15""", [start])
        d["uas"] = _fetch(cur, f"""
            SELECT coalesce(nullif(user_agent, ''), '(sin UA)') AS k, count(*) AS n
            FROM requests WHERE ts >= %s AND {_EXCL}
            GROUP BY k ORDER BY n DESC LIMIT 12""", [start])

        # Alertas del período: severidad + reglas top.
        sev = {r["severity"]: r["n"] for r in _fetch(cur,
               "SELECT severity, count(*) AS n FROM alerts WHERE ts >= %s GROUP BY severity",
               [start])}
        d["severity"] = [{"k": s, "n": sev.get(s, 0)}
                         for s in ("critical", "high", "medium", "low", "info")]
        d["rules"] = _fetch(cur, """
            SELECT rule AS k, count(*) AS n FROM alerts WHERE ts >= %s
            GROUP BY k ORDER BY n DESC LIMIT 10""", [start])

        # NUEVOS VECTORES: paths cuyo PRIMER avistamiento histórico cae en el período.
        d["new_vectors"] = _fetch(cur, f"""
            SELECT path AS k, count(*) AS n, min(ts) AS first
            FROM requests
            WHERE path IS NOT NULL AND {_EXCL}
            GROUP BY path
            HAVING min(ts) >= %s
            ORDER BY n DESC, first DESC
            LIMIT 25""", [start])

    return d


# --------------------------------------------------------------------------- #
# Render (HTML/CSS, email-safe)
# --------------------------------------------------------------------------- #

def e(x):
    return html.escape("" if x is None else str(x))


def pct(cur_v, prev_v):
    """Delta % con flecha; devuelve (texto, color)."""
    if prev_v == 0:
        return ("nuevo" if cur_v else "—", DIM if not cur_v else BRAND_ACCENT)
    change = (cur_v - prev_v) / prev_v * 100
    arrow = "▲" if change > 0 else ("▼" if change < 0 else "=")
    color = "#e66767" if change > 0 else (BRAND_ACCENT if change < 0 else DIM)
    return (f"{arrow} {abs(change):.0f}%", color)


def kpi_tile(label, value, delta):
    txt, col = delta
    return (
        f'<td style="padding:6px">'
        f'<div style="background:{PANEL2};border:1px solid {BORDER};border-radius:10px;padding:14px 16px">'
        f'<div style="color:{DIM};font-size:11px;text-transform:uppercase;letter-spacing:.5px">{e(label)}</div>'
        f'<div style="color:{INK};font-size:26px;font-weight:700;margin-top:4px">{e(f"{value:,}".replace(",", "."))}</div>'
        f'<div style="color:{col};font-size:12px;margin-top:2px">{e(txt)} <span style="color:{DIM}">vs período previo</span></div>'
        f'</div></td>'
    )


def hbars(rows, color=None, maxrows=None, label_key="k", val_key="n", mono=True):
    """Barras horizontales con ancho %. color: str fijo, dict por k, o None=categórico."""
    rows = [r for r in rows if r.get(val_key, 0)]
    if maxrows:
        rows = rows[:maxrows]
    if not rows:
        return f'<div style="color:{DIM};font-size:13px;padding:8px 0">sin datos en el período</div>'
    mx = max(r[val_key] for r in rows) or 1
    ff = "ui-monospace,Menlo,monospace" if mono else "inherit"
    out = ['<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
           'style="border-collapse:collapse">']
    for i, r in enumerate(rows):
        if isinstance(color, dict):
            c = color.get(r[label_key], CAT[i % len(CAT)])
        elif color:
            c = color
        else:
            c = CAT[i % len(CAT)]
        w = max(2, round(r[val_key] / mx * 100))
        out.append(
            '<tr>'
            f'<td style="padding:3px 8px 3px 0;white-space:nowrap;max-width:360px;overflow:hidden;'
            f'text-overflow:ellipsis;font-family:{ff};font-size:12px;color:{INK}">{e(r[label_key])}</td>'
            f'<td style="width:55%;padding:3px 0">'
            f'<div style="background:{c};height:14px;width:{w}%;border-radius:0 4px 4px 0;min-width:3px"></div>'
            '</td>'
            f'<td style="padding:3px 0 3px 8px;text-align:right;font-family:ui-monospace,Menlo,monospace;'
            f'font-size:12px;color:{DIM};white-space:nowrap">{e(f"{r[val_key]:,}".replace(",", "."))}</td>'
            '</tr>')
    out.append('</table>')
    return "".join(out)


def daybars(rows, color, days=14):
    """Mini-barras verticales por día (tendencia). rows: [{d, n}]."""
    by = {r["d"].date(): r["n"] for r in rows}
    today = datetime.now(timezone.utc).date()
    seq = [(today - timedelta(days=days - 1 - i)) for i in range(days)]
    vals = [by.get(day, 0) for day in seq]
    mx = max(vals) or 1
    cells = []
    for day, v in zip(seq, vals):
        h = max(2, round(v / mx * 60))
        cells.append(
            '<td style="vertical-align:bottom;padding:0 2px;text-align:center">'
            f'<div title="{e(day.isoformat())}: {v}" style="background:{color};width:16px;'
            f'height:{h}px;border-radius:3px 3px 0 0;margin:0 auto"></div>'
            f'<div style="color:{DIM};font-size:9px;margin-top:3px">{day.day}</div>'
            '</td>')
    return ('<table role="presentation" cellpadding="0" cellspacing="0" '
            'style="border-collapse:collapse;height:80px"><tr>' + "".join(cells) + '</tr></table>')


def card(title, inner, sub=""):
    subhtml = f'<div style="color:{DIM};font-size:11px;margin-bottom:10px">{e(sub)}</div>' if sub else ""
    return (
        f'<div style="background:{PANEL};border:1px solid {BORDER};border-radius:12px;'
        f'padding:16px 18px;margin-bottom:16px">'
        f'<div style="color:{INK};font-size:14px;font-weight:600;margin-bottom:4px">{e(title)}</div>'
        f'{subhtml}{inner}</div>'
    )


def table_rows(rows, headers, cols, mono_last=True):
    th = "".join(f'<th style="text-align:left;padding:6px 8px;color:{DIM};font-weight:500;'
                 f'font-size:11px;text-transform:uppercase;border-bottom:1px solid {BORDER}">{e(h)}</th>'
                 for h in headers)
    trs = []
    for r in rows:
        tds = []
        for j, c in enumerate(cols):
            align = "right" if (mono_last and j == len(cols) - 1) else "left"
            ff = "ui-monospace,Menlo,monospace"
            val = c(r) if callable(c) else r.get(c, "")
            tds.append(f'<td style="padding:6px 8px;text-align:{align};font-family:{ff};'
                       f'font-size:12px;color:{INK};border-bottom:1px solid {BORDER};'
                       f'max-width:460px;overflow:hidden;text-overflow:ellipsis">{e(val)}</td>')
        trs.append(f"<tr>{''.join(tds)}</tr>")
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
            f'style="border-collapse:collapse"><tr>{th}</tr>{"".join(trs)}</table>')


def render(d, scope="private"):
    public = scope == "public"
    start, now, hours = d["start"], d["now"], d["hours"]
    period = f"{start.strftime('%d/%m %H:%M')} → {now.strftime('%d/%m %H:%M')} UTC (últimas {hours} h)"
    cur, prev = d["cur"], d["prev"]
    new_n = len(d["new_vectors"])

    # KPIs
    kpis = (
        '<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>'
        + kpi_tile("Requests", cur["reqs"], pct(cur["reqs"], prev["reqs"]))
        + kpi_tile("IPs únicas", cur["ips"], pct(cur["ips"], prev["ips"]))
        + kpi_tile("Con body", cur["withbody"], pct(cur["withbody"], prev["withbody"]))
        + '</tr><tr>'
        + kpi_tile("Alertas", cur["alerts"], pct(cur["alerts"], prev["alerts"]))
        + kpi_tile("Honeytokens", d["ht_trig"], ("—", DIM))
        + kpi_tile("Vectores nuevos", new_n, ("en el período", BRAND_ACCENT if new_n else DIM))
        + '</tr></table>'
    )

    parts = [kpis]

    # Tendencia 14 días (requests + alertas)
    trend = (
        f'<div style="color:{DIM};font-size:11px;margin-bottom:6px">Requests por día</div>'
        + daybars(d["daily_reqs"], CAT[0])
        + f'<div style="color:{DIM};font-size:11px;margin:14px 0 6px">Alertas por día</div>'
        + daybars(d["daily_alerts"], SEVC["high"])
    )
    parts.append(card("Tendencia (14 días)", trend))

    # Actividad por hora (período)
    parts.append(card(f"Actividad por hora (últimas {hours} h)",
                      hbars([{"k": r["h"].strftime("%d/%m %H:00"), "n": r["n"]} for r in d["hourly"]],
                            color=CAT[0])))

    # Métodos + Status (dos tarjetas)
    parts.append(card("Métodos HTTP", hbars(d["methods"], color=None)))
    parts.append(card("Status devueltos", hbars(d["status"], color=None)))

    # Severidad de alertas + reglas top
    parts.append(card("Alertas por severidad", hbars(d["severity"], color=SEVC)))
    if d["rules"]:
        parts.append(card("Reglas que más dispararon", hbars(d["rules"], color=CAT[4])))

    # Top paths / IPs
    parts.append(card("Top paths atacados", hbars(d["paths"], color=CAT[0])))
    parts.append(card("Top IPs atacantes", hbars(d["ips"], color=CAT[1])))

    # NUEVOS VECTORES
    if d["new_vectors"]:
        nv = table_rows(
            d["new_vectors"],
            ["path (primera vez en el período)", "hits", "visto por 1ª vez"],
            ["k", lambda r: f"{r['n']:,}".replace(",", "."),
             lambda r: r["first"].strftime("%d/%m %H:%M")],
        )
        parts.append(card(f"Vectores nuevos ({new_n})",
                          nv, sub="Paths cuyo primer avistamiento histórico cae en este período."))

    # User-agents
    parts.append(card("Top user-agents",
                      table_rows(d["uas"], ["user-agent", "hits"],
                                 ["k", lambda r: f"{r['n']:,}".replace(",", ".")])))

    body = "".join(parts)

    pub_badge = (f'<span style="background:{PANEL2};border:1px solid {BORDER};color:{DIM};'
                 f'font-size:11px;padding:2px 8px;border-radius:10px;margin-left:8px">público · agregados</span>'
                 if public else "")
    source_note = ("Datos agregados de un sensor honeypot de OpenBash. No se publican cuerpos de "
                   "request ni la identidad del sensor." if public else
                   "Reporte interno — reverse-scann.")

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>reverse-scann · reporte {e(now.strftime('%d/%m/%Y'))}</title>
<style>
  body {{ margin:0; background:{BG}; color:{INK};
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  a {{ color:{BRAND_MAGENTA}; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:0 16px 40px; }}
</style></head>
<body>
<div style="background:linear-gradient(90deg,{BRAND_NAVY} 0%,{BRAND_MAGENTA} 100%);
     padding:22px 0;margin-bottom:8px">
  <div class="wrap" style="padding-bottom:0">
    <div style="color:#fff;font-size:20px;font-weight:700;letter-spacing:.3px">
      OpenBash · reverse-scann {pub_badge}</div>
    <div style="color:rgba(255,255,255,.85);font-size:13px;margin-top:3px">
      Reporte de actividad del honeypot</div>
    <div style="color:rgba(255,255,255,.7);font-size:12px;margin-top:8px">{e(period)}</div>
  </div>
</div>
<div class="wrap">
  {body}
  <div style="color:{DIM};font-size:11px;border-top:1px solid {BORDER};padding-top:14px;margin-top:8px">
    {e(source_note)} · generado {e(now.strftime('%Y-%m-%d %H:%M UTC'))} ·
    <a href="https://github.com/openbashok/attack-vectors">openbashok/attack-vectors</a>
  </div>
</div>
</body></html>"""


# --------------------------------------------------------------------------- #
# Render "estilo pentest" (claro, A4) — para PDF vía Gotenberg.
# Replica el formato del Executive Report del scanner (generate_executive_report.php):
# Helvetica, #1a1a1a, títulos navy #2A2759, acento magenta #BF0D57, pills de
# severidad con los MISMOS colores, cards .finding, footer gris. Gotenberg (Chromium)
# renderiza esto a PDF A4.
# --------------------------------------------------------------------------- #

PC1 = "#2A2759"   # navy (títulos)  = reportColor1 del scanner
PC2 = "#BF0D57"   # magenta (acento) = reportColor2 del scanner
# severidad (texto / fondo) idénticos al executive report
PSEV = {
    "critical": ("#7B1FA2", "#F3E5F5"), "high": ("#C62828", "#FFEBEE"),
    "medium": ("#E65100", "#FFF3E0"), "low": ("#2E7D32", "#E8F5E9"),
    "info": ("#1565C0", "#E3F2FD"),
}
PCAT = [PC1, PC2, "#1565C0", "#E65100", "#2E7D32", "#7B1FA2", "#00838F", "#5D4037"]


def pbars(rows, color=None, maxrows=None, lk="k", vk="n"):
    rows = [r for r in rows if r.get(vk, 0)]
    if maxrows:
        rows = rows[:maxrows]
    if not rows:
        return '<div style="color:#999;font-size:9pt;padding:6px 0">sin datos en el período</div>'
    mx = max(r[vk] for r in rows) or 1
    out = ['<table style="width:100%;border-collapse:collapse">']
    for i, r in enumerate(rows):
        c = color.get(r[lk], "#999") if isinstance(color, dict) else (color or PCAT[i % len(PCAT)])
        w = max(2, round(r[vk] / mx * 100))
        out.append(
            '<tr>'
            f'<td style="padding:2px 8px 2px 0;white-space:nowrap;max-width:340px;overflow:hidden;'
            f'text-overflow:ellipsis;font-family:ui-monospace,Menlo,monospace;font-size:8.5pt;color:#1a1a1a">{e(r[lk])}</td>'
            f'<td style="width:52%;padding:2px 0"><div style="background:#f0f0f3;border-radius:3px">'
            f'<div style="background:{c};height:11px;width:{w}%;border-radius:3px;min-width:2px"></div></div></td>'
            f'<td style="padding:2px 0 2px 8px;text-align:right;font-family:ui-monospace,Menlo,monospace;'
            f'font-size:8.5pt;color:#888;white-space:nowrap">{e(f"{r[vk]:,}".replace(",", "."))}</td></tr>')
    out.append('</table>')
    return "".join(out)


def ptable(rows, headers, cols):
    th = "".join(f'<th style="text-align:left;padding:5px 8px;background:#fafafa;font-size:7.5pt;'
                 f'text-transform:uppercase;letter-spacing:1px;color:#888;font-weight:700;'
                 f'border-bottom:1px solid #e8e8e8">{e(h)}</th>' for h in headers)
    trs = []
    for r in rows:
        tds = []
        for j, c in enumerate(cols):
            al = "right" if j == len(cols) - 1 else "left"
            val = c(r) if callable(c) else r.get(c, "")
            tds.append(f'<td style="padding:5px 8px;text-align:{al};font-family:ui-monospace,Menlo,monospace;'
                       f'font-size:8.5pt;color:#1a1a1a;border-bottom:1px solid #f0f0f0;'
                       f'max-width:430px;overflow:hidden;text-overflow:ellipsis">{e(val)}</td>')
        trs.append(f"<tr>{''.join(tds)}</tr>")
    return (f'<table style="width:100%;border-collapse:collapse"><tr>{th}</tr>{"".join(trs)}</table>')


def ppill(sev, label=None):
    fg, bg = PSEV.get(sev, PSEV["info"])
    return (f'<span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:8pt;'
            f'font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:{fg};background:{bg}">'
            f'{e(label or sev)}</span>')


def psection(title, inner):
    return (f'<h2 style="font-size:12.5pt;color:{PC1};border-bottom:1px solid #eee;padding-bottom:5px;'
            f'margin:22px 0 10px;font-weight:700">{e(title)}</h2>{inner}')


def pday(rows, color, days=14):
    by = {r["d"].date(): r["n"] for r in rows}
    today = datetime.now(timezone.utc).date()
    seq = [today - timedelta(days=days - 1 - i) for i in range(days)]
    vals = [by.get(x, 0) for x in seq]
    mx = max(vals) or 1
    cells = "".join(
        '<td style="vertical-align:bottom;padding:0 2px;text-align:center">'
        f'<div style="background:{color};width:15px;height:{max(2, round(v/mx*52))}px;border-radius:2px 2px 0 0;margin:0 auto"></div>'
        f'<div style="color:#aaa;font-size:7pt;margin-top:2px">{x.day}</div></td>'
        for x, v in zip(seq, vals))
    return f'<table style="border-collapse:collapse;height:72px"><tr>{cells}</tr></table>'


def render_pdf(d, scope="private"):
    public = scope == "public"
    start, now, hours = d["start"], d["now"], d["hours"]
    cur, prev = d["cur"], d["prev"]
    new_n = len(d["new_vectors"])
    fmtn = lambda n: f"{n:,}".replace(",", ".")

    def kpirow(label, value, delta):
        txt, _ = delta
        return (f'<td style="border:1px solid #e8e8e8;border-radius:4px;padding:10px 12px;width:33%">'
                f'<div style="font-size:7.5pt;text-transform:uppercase;letter-spacing:.8px;color:#888">{e(label)}</div>'
                f'<div style="font-size:19pt;font-weight:700;color:#1a1a1a;margin:2px 0">{e(fmtn(value))}</div>'
                f'<div style="font-size:8pt;color:#999">{e(txt)} vs período previo</div></td>')

    kpis = (
        '<table style="width:100%;border-collapse:separate;border-spacing:6px"><tr>'
        + kpirow("Requests", cur["reqs"], pct(cur["reqs"], prev["reqs"]))
        + kpirow("IPs únicas", cur["ips"], pct(cur["ips"], prev["ips"]))
        + kpirow("Con body", cur["withbody"], pct(cur["withbody"], prev["withbody"]))
        + '</tr><tr>'
        + kpirow("Alertas", cur["alerts"], pct(cur["alerts"], prev["alerts"]))
        + kpirow("Honeytokens", d["ht_trig"], ("—", ""))
        + kpirow("Vectores nuevos", new_n, ("en el período", ""))
        + '</tr></table>')

    # severidad con pills
    sevrows = "".join(
        f'<tr><td style="padding:4px 8px;border-bottom:1px solid #f0f0f0">{ppill(s["k"], s["k"])}</td>'
        f'<td style="padding:4px 8px;text-align:right;font-family:ui-monospace,Menlo,monospace;'
        f'font-size:9pt;border-bottom:1px solid #f0f0f0">{e(fmtn(s["n"]))}</td></tr>'
        for s in d["severity"])
    sevtable = f'<table style="width:auto;border-collapse:collapse">{sevrows}</table>'

    secs = []
    secs.append(psection("Resumen ejecutivo", kpis))
    secs.append(psection("Tendencia (14 días)",
        f'<div style="font-size:8pt;color:#888;margin-bottom:4px">Requests por día</div>{pday(d["daily_reqs"], PC1)}'
        f'<div style="font-size:8pt;color:#888;margin:10px 0 4px">Alertas por día</div>{pday(d["daily_alerts"], PC2)}'))
    secs.append(psection(f"Actividad por hora (últimas {hours} h)",
        pbars([{"k": r["h"].strftime("%d/%m %H:00"), "n": r["n"]} for r in d["hourly"]], color=PC1)))
    secs.append(psection("Alertas por severidad", sevtable))
    if d["rules"]:
        secs.append(psection("Reglas que más dispararon", pbars(d["rules"], color=PC2)))
    secs.append(psection("Métodos HTTP", pbars(d["methods"])))
    secs.append(psection("Status devueltos", pbars(d["status"])))
    secs.append(psection("Top paths atacados", pbars(d["paths"], color=PC1)))
    secs.append(psection("Top IPs atacantes", pbars(d["ips"], color=PC2)))
    if d["new_vectors"]:
        secs.append(psection(f"Vectores nuevos ({new_n})", ptable(
            d["new_vectors"], ["Path (primera vez en el período)", "Hits", "Visto 1ª vez"],
            ["k", lambda r: fmtn(r["n"]), lambda r: r["first"].strftime("%d/%m %H:%M")])))
    secs.append(psection("Top user-agents", ptable(
        d["uas"], ["User-agent", "Hits"], ["k", lambda r: fmtn(r["n"])])))
    body = "".join(secs)

    pub = (" · edición pública (agregados)" if public else "")
    foot = ("Datos agregados de un sensor honeypot de OpenBash. No se publican cuerpos de request "
            "ni la identidad del sensor." if public else "Documento interno — OpenBash reverse-scann.")

    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<style>
  @page {{ size: A4; margin: 14mm 13mm; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Helvetica Neue', Arial, sans-serif; color:#1a1a1a; font-size:10.5pt;
    line-height:1.5; margin:0; }}
  .hdr {{ border-bottom:3px solid {PC2}; padding-bottom:12px; margin-bottom:6px; }}
  .hdr .brand {{ font-size:8pt; letter-spacing:2px; text-transform:uppercase; color:{PC2}; font-weight:700; }}
  .hdr h1 {{ font-size:20pt; margin:4px 0 2px; color:{PC1}; font-weight:700; }}
  .hdr .meta {{ font-size:9pt; color:#777; }}
  table {{ page-break-inside:auto; }}
  h2 {{ page-break-after:avoid; }}
  .foot {{ margin-top:24px; padding-top:10px; border-top:1px solid #eee; font-size:7.5pt;
    color:#aaa; text-align:center; }}
</style></head><body>
  <div class="hdr">
    <div class="brand">OpenBash · reverse-scann{pub}</div>
    <h1>Reporte de actividad — Honeypot</h1>
    <div class="meta">Período: {e(start.strftime('%d/%m/%Y %H:%M'))} → {e(now.strftime('%d/%m/%Y %H:%M'))} UTC
      (últimas {hours} h) · generado {e(now.strftime('%Y-%m-%d %H:%M UTC'))}</div>
  </div>
  {body}
  <div class="foot">{e(foot)}</div>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Reporte HTML del honeypot reverse-scann")
    ap.add_argument("--scope", choices=["private", "public"], default="private")
    ap.add_argument("--style", choices=["web", "pdf"], default="web",
                    help="web = HTML oscuro (mail/web); pdf = estilo pentest claro (Gotenberg)")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--out", default="-", help="archivo de salida ('-' = stdout)")
    args = ap.parse_args()
    data = gather(args.hours)
    renderer = render_pdf if args.style == "pdf" else render
    htmlout = renderer(data, scope=args.scope)
    if args.out == "-":
        print(htmlout)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(htmlout)
        print(f"escrito {args.out} ({len(htmlout)} bytes)")


if __name__ == "__main__":
    main()
