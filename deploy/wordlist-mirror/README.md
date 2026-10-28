# Espejo del diccionario de vectores (wordlist mirror)

Lleva el diccionario de vectores (paths capturados) del honeypot a **dos destinos**, de
forma **automática y segura**:

- **NFS** → `/var/nfs/wordlists/` (nodo-dev lo lee de `/mnt/nfs/wordlists/`, operativo).
- **Repo público** → [`openbashok/attack-vectors`](https://github.com/openbashok/attack-vectors)
  (versionado + comunidad; lo baja quien quiera con `git`/`curl`).

## Principio de seguridad: PULL, no PUSH

El honeypot es la caja más atacada (internet-facing). **No tiene ninguna credencial hacia
nuestra infra.** El **fileserver** (always-on, monta el NFS) es quien **inicia** la conexión y
tira (pull) del honeypot. Si el honeypot se comprometiera, el daño queda ahí.

```
internet ─▶ honeypot (reverse-scann, público)
                 ▲  solo exporta wordlists (comando forzado, sin shell)
                 │  PULL read-only (el fileserver inicia)
            fileserver ──▶ NFS  ──▶ nodo-dev (/mnt/nfs/wordlists)
                 └── deploy key (write, 1 repo) ──▶ github openbashok/attack-vectors ──▶ cualquiera
```

## Piezas

| Dónde | Archivo | Qué hace |
|---|---|---|
| honeypot | `/usr/local/bin/wordlist-export.sh` | imprime las wordlists (paths/paths-common/files/segments/uris) desde el dashboard loopback |
| honeypot | `~/.ssh/authorized_keys` | la mirror key entra **restringida** (`command="…wordlist-export.sh",no-pty,no-*-forwarding`) → solo exporta |
| fileserver | `~/.ssh/id_wordlist_mirror` | clave del mirror (pull al honeypot + deploy key de github) |
| fileserver | `~/attack-vectors` | clone del repo público (remote `git@github-wordlist:…`) |
| fileserver | `/root/mirror_wordlist.sh` | pull → NFS → commit/push (con sanity check y sanitización) |
| fileserver | `~/.mailgun.cred` (600) | `MAILGUN_KEY` + `MAIL_TO` para la alerta de tamaño (fuera del repo público) |
| fileserver | crontab | `0 * * * *` (cada hora; solo commitea si hubo cambios) |

## Sin retención + alerta de tamaño

No se borra ningún snapshot (crece libre). El único control es una **alerta por mail** (Mailgun,
`alertas@m.openbash.com` → vos) **solo en la transición** a tamaño "exagerado": si
`paths.txt > MAX_BYTES` (default 200 MB) manda un mail una vez y pone un marker; cuando vuelve a
la normalidad borra el marker y rearma. Umbral configurable: `MAX_BYTES=... /root/mirror_wordlist.sh`.
La key de Mailgun **no está en el repo** (es público): vive en `~/.mailgun.cred` del fileserver.

## Setup (ya aplicado; referencia para rehacerlo)

1. **Fileserver**: `ssh-keygen -t ed25519 -f ~/.ssh/id_wordlist_mirror` (sin passphrase).
2. **Honeypot**: copiar `wordlist-export.sh` a `/usr/local/bin/`, `chmod +x`, y agregar la
   pubkey del fileserver a `~/.ssh/authorized_keys` con el prefijo
   `command="/usr/local/bin/wordlist-export.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty`.
3. **GitHub**: agregar esa pubkey como **deploy key read-write** de `attack-vectors`
   (`gh repo deploy-key add mirror.pub --repo openbashok/attack-vectors --allow-write`).
4. **Fileserver**: `~/.ssh/config` con `Host github-wordlist` → `HostName github.com`,
   `IdentityFile ~/.ssh/id_wordlist_mirror`; luego
   `git clone git@github-wordlist:openbashok/attack-vectors.git ~/attack-vectors`.
5. **Fileserver**: copiar `mirror_wordlist.sh` a `/root/`, `chmod +x`, probar, y cron diario.

## Reporte diario en PDF (Gotenberg) — por mail

Además del diccionario, el fileserver manda un **reporte diario de actividad del honeypot
en PDF** (mismo formato que los reportes de pentest: HTML → Gotenberg → PDF A4).

```
honeypot (dashboard /api/report, genera HTML estilo-pentest)
     ▲ pull "report" (mismo comando forzado, rama SSH_ORIGINAL_COMMAND=report)
     │
fileserver: report_pdf.sh ──HTML──▶ Gotenberg (red privada) ──PDF──▶ Mailgun ──▶ mail
```

- **Honeypot**: `GET /api/report?scope=private&style=pdf&hours=24` arma el HTML (loopback).
  El `wordlist-export.sh` ramifica por `$SSH_ORIGINAL_COMMAND`: sin arg = wordlists (mirror
  horario), `report` = el HTML del reporte. **Misma clave, mismo comando forzado**, sin aflojar
  la restricción. El honeypot NO toca la red privada ni el Gotenberg: solo genera HTML.
- **Fileserver**: `report_pdf.sh` (cron `5 11 * * *` = **08:05 ART**) tira el HTML, lo postea al
  **Gotenberg del scanner** (reusado solo como servicio de render, por la privada) y manda el PDF
  por Mailgun (`~/.mailgun.cred`). Si el dashboard o Gotenberg fallan, aborta sin mandar nada.
- **No mezcla con scannerOSCP**: solo reusa su Gotenberg stateless; no toca su código ni sus datos.

**Página pública (GitHub Pages).** El mismo `report_pdf.sh` también publica una versión **pública
agregada** (sin identidad del sensor ni bodies) en un repo con Pages:
- Honeypot modo `report-public` → `GET /api/report?scope=public&style=web` (HTML oscuro).
- Fileserver: pull → escribe `index.html` en el clone `~/honeypot-report` (deploy key de escritura
  `~/.ssh/id_honeypot_report`, alias ssh `github-honeypot-report`) → commit/push (autor `noreply`).
- Config: `PUBLIC_REPORT_DIR` en `~/.reverse-scann.conf`. Si no está, el paso se saltea (el mail igual sale).
- Es **best-effort**: si el pull/push público falla, el mail NO se ve afectado.

## Consumir desde nodo-dev

```sh
# operativo (vía NFS, sin credenciales ni internet):
cat /mnt/nfs/wordlists/latest.txt         # = paths-common (vistos >= 3 veces)
ls  /mnt/nfs/wordlists/                     # paths / paths-common / files / segments / uris / uris-safe
# uris      = URI COMPLETA (path + query): preserva el payload (php://input, invokefunction, etc.).
#             OJO: trae metacaracteres de shell (; | $ ( ) ` ...). Tratar como input NO confiable.
# uris-safe = idem pero shell-safe: todo metacaracter de shell/glob/espacio → '_'. Inofensivo
#             aunque se interpole sin comillas. Pensado para consumir directo en pipelines (scannerOSCP).

# o desde el repo público:
curl -s https://raw.githubusercontent.com/openbashok/attack-vectors/main/wordlists/paths-common.txt
```
