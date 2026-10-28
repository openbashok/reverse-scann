# reverse-scann — honeypot HTTP para capturar escaneos de seguridad

Servidor web trampa (OpenResty = nginx + Lua) que registra **cada request HTTP/HTTPS
completa** que recibe — método, URI, query string, headers, request line cruda y cuerpo
POST/PUT (texto o binario) — y la almacena en **PostgreSQL** para analizarla después,
a mano o con algoritmos de clasificación.

Presenta hacia afuera una **identidad configurable** ("persona"): el header `Server`,
la página de inicio, el 404 y rutas custom (ej. señuelos de WordPress) se definen por
perfil y se eligen desde el dashboard — **siempre un único perfil activo**, para que la
identidad sea coherente y no se delate como honeypot.

> ## ⚠️ Uso autorizado únicamente
> Esta es una herramienta **defensiva**. El honeypot captura tráfico que te mandan a vos;
> el `replay_scanner.py` reproduce esos ataques y **debe usarse solo contra sistemas
> propios o con autorización explícita**. No lo uses para atacar terceros. El software se
> provee "as is", sin garantías (ver `LICENSE`). El uso es responsabilidad de quien lo corre.

## Arquitectura

```
scanner ──HTTP/HTTPS──▶ OpenResty (honeypot)
                           │  access: lee el body
                           │  log:    arma el registro
                           │  timer:  INSERT no bloqueante (pgmoon)
                           ▼
                        PostgreSQL (tabla requests, headers en JSONB)
                           ▲   │
                 (solo lee) │   └─ si la DB está caída → fallback JSONL en ./data/captures/
                        Dashboard (Flask) ──▶ http://localhost:8088
```

- La captura corre en la fase `log` de nginx y el INSERT en un `ngx.timer`, así el
  guardado **nunca demora ni delata** la respuesta al scanner.
- También se registran las requests que nginx rechaza con 400 (ej. path traversal
  crudo en la request line).
- Los bodies binarios se guardan en base64 (`body_encoding='base64'`); los de más de
  `CAPTURE_MAX_BODY` bytes (default 256 KB) se truncan y se marca `body_truncated`.
- Si PostgreSQL no responde, ningún registro se pierde: cae a
  `./data/captures/fallback-YYYY-MM-DD.jsonl`.

## Uso

```sh
cp .env.example .env     # ajustá puertos y DB_PASS
docker compose up -d --build
```

Queda escuchando en:

| Puerto host | Servicio |
|---|---|
| 9080 | HTTP |
| 9443 | HTTPS (cert autofirmado, se genera solo en `./certs/`) |
| 127.0.0.1:8088 | Dashboard web de inspección |
| 127.0.0.1:5433 | PostgreSQL (para conectarse desde el host) |

Puertos y credenciales se configuran en `.env` (ver `.env.example`):
`HTTP_PORT`, `HTTPS_PORT`, `DB_HOST_PORT`, `DASHBOARD_PORT`, `DB_NAME`, `DB_USER`,
`DB_PASS`, `CAPTURE_MAX_BODY`, `TLS_CN`.

> **En producción** exponer 80/443 (`HTTP_PORT=80 HTTPS_PORT=443`) y cambiar
> `DB_PASS`. La base nunca se expone fuera de loopback.

## Identidad configurable (personas)

El honeypot presenta una **persona** a la vez — nunca dos en paralelo, porque respuestas
contradictorias (ej. Apache y nginx al mismo tiempo) delatarían el honeypot. Cada perfil
(tabla `profiles`) define:

- `server_header` — lo que ve el mundo (ej. `Apache/2.4.41 (Ubuntu)`, `nginx/1.18.0`, `Microsoft-IIS/10.0`).
- `index_body` / `index_status` — respuesta de `/`.
- `notfound_body` / `notfound_status` — respuesta para paths sin ruta.
- `extra_headers` — headers globales (ej. `X-Powered-By`, `Link` para simular WordPress).
- `routes` — rutas custom `[{match, match_type (exact|prefix|pattern), status, content_type, headers, body}]`
  para **cebar scanners específicos** (ej. `/wp-login.php`, `/xmlrpc.php`, `/wp-json`).

El honeypot (Lua) lee el perfil activo desde Postgres a un shared dict, refrescado cada
~4 s, así los cambios se aplican en vivo **sin reiniciar**. Si no hay DB ni perfil activo,
cae a una persona Apache por defecto. Vienen tres perfiles seed: `apache-ubuntu` (activo),
`nginx` y `wordpress-apache`. Se editan y activan desde la pestaña **Identidad** del dashboard.

> Las respuestas servidas son estáticas (definidas por vos); el honeypot **nunca refleja
> la entrada del atacante** en el cuerpo, así que no hay XSS reflejado desde el honeypot.

### Importar cebos de h0neytr4p

`scripts/import_h0neytr4p_traps.py` convierte las "traps" de
[h0neytr4p](https://github.com/pbssubhash/h0neytr4p) (Apache-2.0) a nuestro modelo de
rutas y crea un perfil `h0neytr4p-traps` con ~34 cebos (CVEs Citrix/Cisco/VMware/Spring,
default-creds Jenkins/Jira/Zabbix/RabbitMQ, config leaks `.git`/`.env`/`nginx.conf`, etc.).
Los globs `*` de h0neytr4p se mapean a `exact`/`prefix`/`pattern`; los bodies > 256 KB se
truncan (y se avisa).

```sh
python3 scripts/import_h0neytr4p_traps.py /ruta/al/checkout/h0neytr4p --activate
```

> Este perfil agrupa **todos** los cebos, así que responde como muchos productos a la vez:
> máxima cobertura, **poco sigilo**. Para una identidad coherente, copiá desde el dashboard
> solo las rutas que te sirvan a un perfil propio. (La captura ocurre igual, respondas lo
> que respondas.) El importador necesita un checkout de h0neytr4p; no viene en este repo.

## Dashboard de inspección

`http://localhost:8088` — SPA con dos pestañas: **Capturas** (inspección, solo lectura) e
**Identidad** (editor de personas). La parte de capturas tiene:

- Tarjetas de resumen: totales, IPs distintas, requests con body, top métodos / IPs /
  paths / user-agents.
- Tabla de requests (más recientes primero) con filtros: búsqueda de texto en
  URI/body/user-agent, IP exacta, método, y "solo con body". Paginación con "cargar más".
- Panel de detalle por request: metadata, URI, **request line + headers crudos**,
  headers parseados y el **body completo** (base64 si es binario, con aviso de truncado).
- Checkbox de auto-refresh (5 s) para ver capturas en vivo durante un escaneo.

El dashboard corre en su propio contenedor (`dashboard/`, Flask + psycopg). Sobre las
capturas solo lee; la escritura se limita a la config de personas.

### Seguridad del dashboard

El dashboard muestra payloads de ataque reales (XSS, SQLi, etc.), así que está endurecido
para que inspeccionarlos sea seguro:

- **Anti stored-XSS al mostrar**: todo dato capturado se inserta en el DOM con
  `textContent` / `createElement` (cero `innerHTML`), nunca como HTML. Un `<script>` o
  `onerror=` guardado se ve como texto y no se ejecuta.
- **CSP estricta** (`script-src 'self'`, sin `unsafe-inline`) + `nosniff` +
  `X-Frame-Options: DENY`: defensa en profundidad — aunque fallara el escape, el navegador
  no ejecuta scripts ni event handlers inyectados. Por eso el JS vive en `/static/app.js`.
- **Anti-SQLi al guardar**: todas las queries son parametrizadas (psycopg). El honeypot
  guarda los payloads **verbatim** (para análisis) pero de forma inyección-segura
  (pgmoon `escape_literal`).
- **Validación de la config de personas**: tipos y rangos (status 100-599), y se rechazan
  CR/LF y bytes de control en nombres/valores de header → evita header/response splitting
  en las respuestas del honeypot.

## Consultar los ataques capturados (CLI)

```sh
./scripts/query.sh              # resumen: totales, top IPs, paths, user-agents, métodos
./scripts/query.sh last 50      # últimas 50 requests
./scripts/query.sh ip 1.2.3.4   # todo lo que mandó una IP
./scripts/query.sh sql "SELECT ... FROM requests ..."
./scripts/query.sh psql         # shell psql interactivo
```

Ejemplos útiles:

```sql
-- Requests con body (posibles payloads de inyección)
SELECT ts, remote_addr, method, uri, body FROM requests WHERE body IS NOT NULL;

-- Buscar SQLi en query string o body
SELECT * FROM requests WHERE uri ILIKE '%union%select%' OR body ILIKE '%'' or ''1''=''1%';

-- Scanners identificados por User-Agent
SELECT DISTINCT user_agent FROM requests
WHERE user_agent ~* 'nikto|nuclei|sqlmap|nmap|zgrab|masscan|wpscan';

-- Headers como JSONB
SELECT remote_addr, headers->>'x-forwarded-for' FROM requests WHERE headers ? 'x-forwarded-for';
```

## Alertas y honeytokens (servicio `alerter`)

Un watcher (contenedor `alerter`, Python) vigila la tabla `requests` y genera alertas,
**desacoplado del hot-path de captura** (solo lee). Por cada request nuevo:

1. **Honeytokens**: busca tokens activos (tabla `honeytokens`) en uri/body/headers. Si uno
   reaparece → alerta `critical`. Un honeytoken es un cebo único que sembrás en respuestas
   (un *canary path* en `robots.txt`, una API key falsa en un `.env` trampa); si vuelve en
   una request, es señal fuerte de que el atacante usó lo que le servimos, y linkea la IP
   que escaneó con la que explota.
2. **Ruleset de alto valor**: regex sobre uri/body/headers — `log4shell` (critical),
   `rce_cmd_injection`/`webshell_php`/`rce_spring_ognl` (high), `path_traversal`/
   `file_read_passwd`/`sqli` (medium), `xss`/`recon_sensitive` (low). Editables en
   `alerter/watcher.py`.

Todo se guarda en la tabla `alerts` (visible en la pestaña **Alertas** del dashboard) y,
si configurás `ALERT_WEBHOOK_URL`, las alertas de severidad ≥ `ALERT_MIN_SEVERITY` se
mandan a un webhook (Slack/Discord/SIEM) con throttle por `(ip, regla)`.

```sh
# habilitar webhook (Slack/Discord/genérico): en .env
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
ALERT_MIN_SEVERITY=high
```

Honeytokens se listan/crean desde el dashboard (o la API `/api/honeytokens`). Un
`canary_path` sin token se autogenera; sembralo vos en una respuesta de la persona activa
(ej. un `robots.txt` con `Disallow: <canary>`) para que el atacante lo descubra y lo pida.

### Whitelist de IPs propias

Tabla `ip_whitelist` (hosts o rangos CIDR) para ignorar tráfico propio (monitor, infra
nuestra). Se administra desde la pestaña **Alertas** del dashboard (o la API `/api/whitelist`).
Efecto: el watcher **no genera alertas** para esas IPs, se **excluyen de los stats** de
Capturas (así el monitor no domina el top de IPs/paths), y el replayer **no las replica**
(salvo `--include-whitelisted`). Acepta host (`1.2.3.4`) o CIDR (`172.104.0.0/16`).

## Replay de ataques contra targets propios (`scripts/replay_scanner.py`)

Scanner "reverso": lee los ataques capturados y los **re-ejecuta tal cual** (mismo método,
path/query crudo, headers y body — texto o base64) contra targets de tu laboratorio. Sirve
para probar tus propios sistemas con el tráfico de ataque real que recibe el honeypot.

Usa `http.client` (no `requests`/`urllib`) para mandar la request line **literal**, así
preserva payloads como `/x/..%252f..%252fetc/passwd` sin normalizarlos. El `Host` se
reescribe al target (salvo `--keep-host`) y el `Content-Length` se recalcula.

```sh
pip install "psycopg[binary]"

# últimos 1000 ataques por fecha, contra un target de lab
python3 scripts/replay_scanner.py --limit 1000 --target http://10.0.0.5

# varios targets desde archivo, 20 en paralelo, guardando resultados
python3 scripts/replay_scanner.py --limit 500 --targets-file lab.txt -c 20 -o out.jsonl

# ver qué se seleccionaría, sin enviar
python3 scripts/replay_scanner.py --limit 50 --target http://10.0.0.5 --dry-run
python3 scripts/replay_scanner.py --limit 50 --path-like passwd --list
```

Por default imprime **una línea por request** con el código de respuesta coloreado (estilo
nuclei): `[200] GET /path  (bytes, ms) target [n/total]`. `-q/--quiet` muestra solo el
resumen; `--no-color` desactiva los colores.

**Nutrirse de las alertas** (recomendado): con `--from-alerts` el replayer selecciona solo
los requests que **dispararon una alerta** del watcher (SQLi, RCE, traversal, honeytokens…),
en vez del stream crudo dominado por ruido (`GET /`). Se refina con `--severity high,medium`
y `--alert-rule sqli,rce_cmd_injection` (ambas implican `--from-alerts`). Así replicás contra
tu lab exactamente el tráfico de ataque de alto valor que recibió el honeypot.

```sh
python3 scripts/replay_scanner.py --severity high,medium --limit 500 --target http://10.0.0.5
python3 scripts/replay_scanner.py --from-alerts --alert-rule sqli --target http://10.0.0.5
```

**Dedup activo por default**: `--limit N` trae los N requests **únicos** más recientes,
donde "único" = combinación distinta de **método + uri + body + headers** (si un atacante
varía algo en el body o en un header, cuenta como request distinto y no se pierde). Con
`--no-dedup` se replica tal cual, repetidos incluidos.

Selección: `--limit N` (últimos N únicos por fecha), `--from-alerts` + `--severity` +
`--alert-rule`, `--method` (uno o varios coma-separados, ej. `--method POST` o
`--method GET,HEAD`), `--path-like`, `--only-body`, `--since`, `--no-dedup`, `--chrono`.
Targets: `--target` (repetible) y/o `--targets-file`.
Ejecución: `-c/--concurrency`, `--timeout`, `--dry-run`, `--yes`, `-o/--output` (JSONL).

> ⚠️ Lanza ataques reales: usalo **solo contra targets que te pertenecen / tenés permiso**
> de testear. Pide confirmación salvo `--yes`.

**Contra la base de un server remoto** (Postgres loopback): tunelear el puerto y apuntar ahí.
Como el `5433` local suele estar tomado por tu propia instancia, usá otro puerto local (ej. `5444`):

```sh
# túnel: 5444 local -> 5433 del server (dejar corriendo)
ssh -f -N -L 5444:127.0.0.1:5433 <tu-server>

# el DB_PASS del server vive en su /opt/reverse-scann/.env; lo traés sin copiarlo a mano:
DBPASS=$(ssh <tu-server> "grep '^DB_PASS=' /opt/reverse-scann/.env | cut -d= -f2-")

python3 scripts/replay_scanner.py --db-port 5444 --db-pass "$DBPASS" \
    --limit 1000 --target http://TU-TARGET-DE-LAB
```

Los `--db-*` (o `--dsn`, o variables `DB_*`) default a la base local `127.0.0.1:5433`.

## Diccionario de vectores (`scripts/build_wordlist.py`)

Genera tu propio **wordlist** (estilo SecLists) con los paths REALES que te piden los bots:
deduplicado y ordenado por frecuencia (los vectores más comunes primero). Ideal para
alimentar fuzzers (ffuf, gobuster, dirsearch…). Toma el path **crudo** (de `uri`, sin query),
así preserva los payloads tal cual (`..%2f`, `%2e%2e`, dobles extensiones). Excluye IPs propias.

```sh
# todos los paths, por frecuencia, sin la barra inicial (para ffuf/gobuster)
python3 scripts/build_wordlist.py --strip-slash -o paths.txt

# solo vectores vistos >= 3 veces (filtra ruido), top 5000
python3 scripts/build_wordlist.py --min-count 3 --top 5000 -o common.txt

# diccionario de nombres de archivo, o de segmentos de path
python3 scripts/build_wordlist.py --mode files -o files.txt
python3 scripts/build_wordlist.py --mode segments -o segments.txt
```

Modos: `paths` (default, el path completo con nombre de archivo), `files` (solo el nombre de
archivo), `segments` (cada dir/archivo por separado). Filtros: `--min-count N`, `--top N`,
`--since`, `--method`. Salida: `--with-count`, `--strip-slash`, `--decode`, `--sort freq|alpha`,
`-o`. Misma base/túnel que el replayer (`--db-*`/`--dsn`/env `DB_*`).

**Desde el dashboard** (pestaña **Ajustes**): el server genera un **snapshot diario**
automático (`wordlist-YYYY-MM-DD.txt`, en el volumen `wordlists`) y los lista para
descargar; además hay un botón para bajar uno **fresco** on-demand con filtros (modo,
min-count, barra inicial). Endpoints: `GET /api/wordlist` (on-demand) y `GET /api/wordlists`
+ `/api/wordlists/<archivo>` (snapshots). El snapshot lo escribe un hilo del dashboard
(revisa cada hora, escribe uno por día) — sin cron ni contenedores extra.

## Esquema (`db/init/01-schema.sql`)

Tabla `requests`: una fila por request. Campos principales: `ts`, `remote_addr` (INET),
`method`, `uri`/`path`/`query`, `headers` (JSONB, claves en minúscula, con índice GIN),
`raw_header` (request line + headers tal cual llegaron, casing original), `body`,
`body_encoding` (`utf8`/`base64`), `body_size`, `body_truncated`, `status`,
`request_time`.

## Estructura del repo

```
docker-compose.yml        # honeypot + postgres + dashboard
openresty/
  Dockerfile              # openresty-alpine-fat + pgmoon + lua-resty-openssl
  nginx.conf              # server catch-all 80/443; responde vía persona.lua
  lua/capture.lua         # captura → INSERT en postgres (fallback JSONL)
  lua/persona.lua         # identidad activa: Server header + rutas custom
  entrypoint.sh           # genera el cert autofirmado y arranca nginx
dashboard/
  Dockerfile              # python-alpine + Flask + psycopg
  app.py                  # API: capturas (RO) + personas + alertas + honeytokens
  templates/index.html    # SPA (tabs Capturas / Alertas / Identidad)
  static/app.js           # lógica del front (externo, para CSP estricta)
alerter/
  Dockerfile              # python-alpine + psycopg
  watcher.py              # watcher: honeytokens + ruleset -> alerts (+ webhook)
.env.example              # plantilla de configuración (copiar a .env)
db/init/01-schema.sql     # tabla requests (solo primer arranque de la DB)
db/init/02-profiles.sql   # tabla profiles + seed de personas
db/init/03-alerts.sql     # tablas alerts + honeytokens + alerter_state
scripts/query.sh          # consultas rápidas
scripts/import_h0neytr4p_traps.py  # importa cebos de h0neytr4p como persona
scripts/replay_scanner.py # replica los ataques capturados contra targets propios
scripts/build_wordlist.py # arma un diccionario de vectores con los paths capturados
data/captures/            # JSONL de fallback (gitignored)
certs/                    # cert autofirmado (gitignored)
```

## Notas operativas

- El honeypot responde según la **persona activa** (200 en `/`, 404 en el resto, más las
  rutas custom); **igual se registra todo**, responda lo que responda.
- Cambiar la identidad: pestaña **Identidad** del dashboard, o
  `./scripts/query.sh sql "UPDATE profiles SET is_active=false WHERE is_active; UPDATE profiles SET is_active=true WHERE name='nginx';"`.
  El honeypot lo toma solo en ~4 s.
- Para resetear los datos: `./scripts/query.sh sql "TRUNCATE requests RESTART IDENTITY;"`.
  Para borrar la base entera: `docker compose down -v`.
- Los scripts de `db/init/` solo corren en el **primer** arranque del volumen `pgdata`;
  si cambiás el esquema/seed sobre una base existente, aplicá el SQL a mano
  (`docker compose exec -T db psql -U honeypot -d honeypot < db/init/02-profiles.sql`).
