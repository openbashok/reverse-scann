#!/usr/bin/env python3
"""build_wordlist — genera un diccionario de paths/vectores desde lo que capturó el honeypot.

Construye tu propio wordlist (estilo SecLists) a partir de los paths REALES que te piden
los bots: deduplicado y ordenado por frecuencia (los vectores más comunes primero). Pensado
para alimentar fuzzers (ffuf, gobuster, dirsearch, feroxbuster…).

Toma el path crudo tal cual llegó (de `uri`, sin el query string), así preserva los payloads
reales (`..%2f`, `%2e%2e`, dobles extensiones, etc.). Excluye las IPs propias (ip_whitelist).

Modos (--mode):
  paths     (default) el path completo, incluido el nombre de archivo   -> /wp-content/.../x.php
  files     solo el nombre de archivo (último segmento)                 -> x.php
  segments  cada segmento del path por separado (dirs + archivos)       -> wp-content, x.php

Requiere: pip install "psycopg[binary]"

Ejemplos:
  # wordlist de todos los paths, por frecuencia, sin la barra inicial (para ffuf/gobuster)
  python3 scripts/build_wordlist.py --strip-slash -o paths.txt

  # solo vectores vistos >= 3 veces (filtra ruido de una sola vez), top 5000
  python3 scripts/build_wordlist.py --min-count 3 --top 5000 -o common.txt

  # diccionario de nombres de archivo únicos
  python3 scripts/build_wordlist.py --mode files -o files.txt

  # contra la base del SERVER: tunelear antes 'ssh -L 5444:127.0.0.1:5433 <tu-server>'
  export DB_PASS=$(ssh <tu-server> "grep '^DB_PASS=' /opt/reverse-scann/.env | cut -d= -f2-")
  python3 scripts/build_wordlist.py --db-port 5444 --since 2026-10-01 -o vectores.txt
"""
import argparse
import os
import sys
from collections import Counter
from urllib.parse import unquote


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def fetch_paths(args):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        sys.exit('Falta psycopg. Instalá:  pip install "psycopg[binary]"')

    dsn = args.dsn or (
        f"host={args.db_host} port={args.db_port} dbname={args.db_name} "
        f"user={args.db_user} password={args.db_pass}"
    )
    where = ["uri <> ''"]
    params = []
    if args.since:
        where.append("ts >= %s")
        params.append(args.since)
    if args.method:
        methods = [m.strip().upper() for m in args.method.split(",") if m.strip()]
        where.append("method = ANY(%s)")
        params.append(methods)
    if not args.include_whitelisted:
        where.append("NOT EXISTS (SELECT 1 FROM ip_whitelist w "
                     "WHERE requests.remote_addr <<= w.cidr)")
    clause = "WHERE " + " AND ".join(where)
    # split_part(uri,'?',1) = el path sin query, crudo (preserva %2e%2e, ..%2f, etc.)
    sql = (f"SELECT split_part(uri, '?', 1) AS path, count(*) AS n "
           f"FROM requests {clause} GROUP BY 1")

    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(sql, params)
                rows = cur.fetchall()
            except psycopg.errors.UndefinedTable:
                conn.rollback()
                sql2 = sql.replace(
                    "NOT EXISTS (SELECT 1 FROM ip_whitelist w "
                    "WHERE requests.remote_addr <<= w.cidr)", "true")
                cur.execute(sql2, params)
                rows = cur.fetchall()
    return [(r["path"], r["n"]) for r in rows if r["path"]]


def transform(pairs, args):
    """Devuelve un Counter {entrada: frecuencia} según el modo."""
    counts = Counter()
    for path, n in pairs:
        if args.decode:
            path = unquote(path)
        if args.mode == "paths":
            entry = path if not args.strip_slash else path.lstrip("/")
            if entry:
                counts[entry] += n
        elif args.mode == "files":
            leaf = path.rstrip("/").rsplit("/", 1)[-1]
            if leaf:
                counts[leaf] += n
        elif args.mode == "segments":
            for seg in path.split("/"):
                if seg:
                    counts[seg] += n
    return counts


def main():
    p = argparse.ArgumentParser(
        description="Genera un wordlist de vectores desde los paths capturados por el honeypot.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--mode", choices=["paths", "files", "segments"], default="paths",
                   help="paths (default) | files (nombre de archivo) | segments (cada segmento)")
    p.add_argument("--min-count", type=int, default=1,
                   help="incluir solo entradas vistas al menos N veces (filtra ruido). Default 1")
    p.add_argument("--top", type=int, help="limitar a las N entradas más frecuentes")
    p.add_argument("--since", help="solo requests con ts >= (ej. '2026-10-01')")
    p.add_argument("--method", help="filtrar por método(s), coma-sep (ej. GET,POST)")
    p.add_argument("--strip-slash", action="store_true",
                   help="sacar la barra inicial de los paths (estilo ffuf/gobuster)")
    p.add_argument("--decode", action="store_true",
                   help="URL-decodificar el path (%%2e%%2e -> ..). Default: crudo")
    p.add_argument("--sort", choices=["freq", "alpha"], default="freq",
                   help="orden de salida: freq (por frecuencia, default) | alpha")
    p.add_argument("--with-count", action="store_true",
                   help="prefijar cada línea con la frecuencia (count<TAB>entrada)")
    p.add_argument("-o", "--output", help="archivo de salida (default: stdout)")
    p.add_argument("--include-whitelisted", action="store_true",
                   help="NO excluir las IPs de ip_whitelist (por default se excluyen)")
    p.add_argument("--dsn", help="DSN completo de psycopg (pisa los --db-*)")
    p.add_argument("--db-host", default=os.getenv("DB_HOST", "127.0.0.1"))
    p.add_argument("--db-port", default=os.getenv("DB_PORT", "5433"))
    p.add_argument("--db-name", default=os.getenv("DB_NAME", "honeypot"))
    p.add_argument("--db-user", default=os.getenv("DB_USER", "honeypot"))
    p.add_argument("--db-pass", default=os.getenv("DB_PASS", "honeypot_dev_pass"))
    args = p.parse_args()

    pairs = fetch_paths(args)
    counts = transform(pairs, args)

    items = [(e, c) for e, c in counts.items() if c >= args.min_count]
    if args.sort == "freq":
        items.sort(key=lambda x: (-x[1], x[0]))
    else:
        items.sort(key=lambda x: x[0])
    if args.top:
        items = items[:args.top]

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    for entry, c in items:
        out.write((f"{c}\t{entry}\n") if args.with_count else (entry + "\n"))
    if args.output:
        out.close()

    eprint(f"{len(items)} entradas ({args.mode}) de {len(pairs)} paths únicos capturados"
           + (f"  ->  {args.output}" if args.output else ""))


if __name__ == "__main__":
    main()
