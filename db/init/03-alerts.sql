-- Alertas y honeytokens. El watcher (servicio alerter) pollea `requests`, evalúa
-- reglas + honeytokens, y escribe acá. Desacoplado del hot-path de captura.

-- Honeytokens: cebos únicos sembrados en respuestas. Si reaparecen en una request,
-- es señal fuerte de que el atacante usó lo que le servimos.
CREATE TABLE IF NOT EXISTS honeytokens (
    id              BIGSERIAL PRIMARY KEY,
    token           TEXT UNIQUE NOT NULL,          -- el string secreto / canary path
    kind            TEXT NOT NULL DEFAULT 'custom', -- canary_path | api_key | credential | custom
    description     TEXT,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    trigger_count   INTEGER NOT NULL DEFAULT 0,
    first_triggered TIMESTAMPTZ,
    last_triggered  TIMESTAMPTZ
);

-- Alertas generadas por el watcher.
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id  BIGINT,                 -- request que la disparó (sin FK dura: requests puede truncarse)
    rule        TEXT NOT NULL,          -- nombre de la regla o honeytoken
    severity    TEXT NOT NULL,          -- info | low | medium | high | critical
    remote_addr INET,
    summary     TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    notified    BOOLEAN NOT NULL DEFAULT false   -- si ya se mandó al webhook
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_addr     ON alerts (remote_addr);

-- Estado del watcher: hasta qué request id procesó (una sola fila).
CREATE TABLE IF NOT EXISTS alerter_state (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    last_request_id BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT alerter_state_singleton CHECK (id = 1)
);
INSERT INTO alerter_state (id, last_request_id) VALUES (1, 0)
    ON CONFLICT (id) DO NOTHING;

-- IPs/rangos propios a ignorar (monitor, infra nuestra, etc.). El watcher no genera
-- alertas para estos, el dashboard los saca de los stats y el replayer no los replica.
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id         BIGSERIAL PRIMARY KEY,
    cidr       INET NOT NULL UNIQUE,   -- host (/32) o red (ej. 172.104.0.0/16)
    note       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Sembrá acá tus propias IPs/rangos a ignorar (tu monitoreo, health-checks, infra), o
-- agregalos desde el dashboard (pestaña Ajustes). Ejemplo (IPs de documentación RFC 5737,
-- reemplazá por las tuyas):
--   INSERT INTO ip_whitelist (cidr, note) VALUES
--       ('192.0.2.10',      'mi monitor / health-check'),
--       ('198.51.100.0/24', 'mi rango de infra')
--   ON CONFLICT (cidr) DO NOTHING;

-- Honeytokens: NO se siembran valores fijos acá a propósito. Un canario con valor
-- conocido (porque está en el repo) no sirve: el atacante lo reconoce y lo evita/envenena.
-- Generá los tuyos, con valor aleatorio, desde el dashboard (pestaña Alertas → Honeytokens;
-- botón "rotar" para regenerarlos). Tipos: canary_path (ej. sembrar en robots.txt),
-- api_key (fake AWS key en un /.env trampa), credential, custom.
