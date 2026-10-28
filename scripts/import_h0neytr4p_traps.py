#!/usr/bin/env python3
"""Importa las traps de h0neytr4p como una persona de reverse-scann.

h0neytr4p (https://github.com/pbssubhash/h0neytr4p, Apache-2.0) define "traps" como
JSON en traps/**/*.json: cada una tiene Behaviour[] con Request (Url con globs '*',
Method) y Response (StatusCode, Body string|archivo, Headers). Esto las convierte a
nuestro modelo de rutas {match, match_type, status, content_type, headers, body} y crea
(o reemplaza) un perfil "h0neytr4p-traps" vía la API del dashboard.

NOTA de sigilo: este perfil agrupa TODAS las traps (Jenkins, Citrix, Jira, WordPress…),
así que responde como muchos productos a la vez — máxima cobertura de cebos, pero NO es
una identidad coherente. Para sigilo, copiá las rutas que te sirvan a un perfil coherente
desde el dashboard. Igual, la captura de cada escaneo ocurre respondas lo que respondas.

Uso:
  python3 scripts/import_h0neytr4p_traps.py /ruta/al/checkout/h0neytr4p \
      [--api http://localhost:8088] [--name h0neytr4p-traps] [--activate]
"""
import argparse
import glob
import json
import os
import sys
import urllib.request

BODY_CAP = 256 * 1024  # bodies más grandes se truncan (no entran cómodos en el shared dict)

LUA_MAGIC = set("().%+-*?[]^$")


def lua_escape(seg):
    return "".join("%" + c if c in LUA_MAGIC else c for c in seg)


def glob_to_match(url):
    """Convierte un glob de h0neytr4p a (match, match_type) nuestro."""
    if "*" not in url:
        return url, "exact"                      # match literal exacto
    parts = url.split("*")
    pat = ".*".join(lua_escape(p) for p in parts)
    if not url.startswith("*"):
        pat = "^" + pat
    if not url.endswith("*"):
        pat = pat + "$"
    return pat, "pattern"                         # string.find(uri, pat) en persona.lua


def infer_content_type(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".html", ".htm"):
        return "text/html"
    if ext == ".json":
        return "application/json"
    return "text/plain"


def load_body(resp, repo_root):
    """Devuelve (body, content_type, truncated) para un Response de trap."""
    rtype = resp.get("Type", "string")
    hdr_ct = None
    for key in ("Headers", "Header"):
        h = resp.get(key)
        if isinstance(h, dict):
            for k, v in h.items():
                if k.lower() == "content-type":
                    hdr_ct = v
    if rtype == "file":
        rel = resp.get("Body", "")
        full = os.path.join(repo_root, rel)
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except OSError as e:
            print(f"  ! no pude leer asset {rel}: {e}", file=sys.stderr)
            return "", hdr_ct or "text/html", False
        truncated = False
        if len(data.encode("utf-8")) > BODY_CAP:
            data = data.encode("utf-8")[:BODY_CAP].decode("utf-8", errors="ignore")
            truncated = True
        return data, hdr_ct or infer_content_type(rel), truncated
    # string
    return resp.get("Body", "") or "", hdr_ct or "text/html", False


def route_headers(resp):
    """Headers de respuesta de la trap, sin Content-Type (lo seteamos aparte)."""
    out = {}
    for key in ("Headers", "Header"):
        h = resp.get(key)
        if isinstance(h, dict):
            for k, v in h.items():
                if k.lower() == "content-type":
                    continue
                out[k] = str(v)
    return out


def convert(repo_root):
    trap_files = sorted(glob.glob(os.path.join(repo_root, "traps", "**", "*.json"),
                                  recursive=True))
    if not trap_files:
        sys.exit(f"No encontré traps en {repo_root}/traps/**/*.json")
    routes, truncated_assets = [], []
    for tf in trap_files:
        try:
            trap = json.load(open(tf, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"  ! trap inválida {tf}: {e}", file=sys.stderr)
            continue
        name = trap.get("BasicInfo", {}).get("Name", os.path.basename(tf))
        for b in trap.get("Behaviour", []):
            req, resp = b.get("Request", {}), b.get("Response", {})
            url = req.get("Url")
            if not url:
                continue
            match, mtype = glob_to_match(url)
            body, ctype, trunc = load_body(resp, repo_root)
            if trunc:
                truncated_assets.append(f"{name}:{url}")
            routes.append({
                "match": match,
                "match_type": mtype,
                "status": int(resp.get("StatusCode", 200)),
                "content_type": ctype,
                "headers": route_headers(resp),
                "body": body,
                "_trap": name,  # se quita antes de enviar; solo para ordenar/debug
            })

    # Orden por especificidad: exactas primero (más largas antes), luego patterns.
    # Así una ruta amplia no tapa una específica (persona.lua = primer match gana).
    routes.sort(key=lambda r: (r["match_type"] != "exact", -len(r["match"])))
    for r in routes:
        r.pop("_trap", None)
    return routes, truncated_assets


def api(base, path, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or "null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or "null")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", help="ruta al checkout de h0neytr4p")
    ap.add_argument("--api", default="http://localhost:8088")
    ap.add_argument("--name", default="h0neytr4p-traps")
    ap.add_argument("--activate", action="store_true", help="activar el perfil al crearlo")
    args = ap.parse_args()

    routes, truncated = convert(args.repo)
    print(f"Convertí {len(routes)} rutas desde las traps de h0neytr4p.")
    if truncated:
        print(f"  {len(truncated)} bodies truncados a {BODY_CAP // 1024} KB: "
              + ", ".join(truncated))

    profile = {
        "name": args.name,
        "server_header": "Apache/2.4.41 (Ubuntu)",
        "index_status": 200,
        "index_body": "<html><body><h1>It works!</h1></body></html>",
        "notfound_status": 404,
        "notfound_body": ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head>'
                          '<title>404 Not Found</title></head><body><h1>Not Found</h1>'
                          '<p>The requested URL was not found on this server.</p><hr>'
                          '<address>Apache/2.4.41 (Ubuntu) Server Port 80</address>'
                          '</body></html>'),
        "extra_headers": {},
        "routes": routes,
    }

    # Reemplazar si ya existe (y no está activo)
    _, listing = api(args.api, "/api/profiles")
    existing = next((p for p in (listing or {}).get("rows", []) if p["name"] == args.name), None)
    if existing:
        if existing["is_active"]:
            sys.exit(f"El perfil '{args.name}' está activo; desactivá otro antes de reimportar.")
        print(f"Reemplazando perfil existente id={existing['id']}…")
        api(args.api, f"/api/profiles/{existing['id']}", "DELETE")

    status, resp = api(args.api, "/api/profiles", "POST", profile)
    if status != 201:
        sys.exit(f"Error creando el perfil ({status}): {resp}")
    pid = resp["id"]
    print(f"Perfil '{args.name}' creado (id={pid}) con {len(routes)} rutas.")

    if args.activate:
        status, resp = api(args.api, f"/api/profiles/{pid}/activate", "POST")
        print("Activado." if status == 200 else f"No pude activar ({status}): {resp}")
    else:
        print("Activalo desde la pestaña Identidad del dashboard, o con --activate.")


if __name__ == "__main__":
    main()
