-- Esquema del honeypot: una fila por request HTTP recibida.
CREATE TABLE IF NOT EXISTS requests (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    remote_addr    INET,
    remote_port    INTEGER,
    scheme         TEXT,
    host           TEXT,
    method         TEXT,
    uri            TEXT,           -- URI completa con query string
    path           TEXT,           -- solo el path, normalizado por nginx
    query          TEXT,           -- query string cruda
    http_version   TEXT,
    user_agent     TEXT,
    headers        JSONB,          -- todos los headers parseados
    raw_header     TEXT,           -- request line + headers tal cual llegaron
    body           TEXT,           -- cuerpo (texto, o base64 si es binario)
    body_encoding  TEXT,           -- 'utf8' | 'base64' | NULL si no hubo body
    body_size      INTEGER,        -- tamaño real del body recibido
    body_truncated BOOLEAN NOT NULL DEFAULT false,
    status         INTEGER,        -- status code que respondimos
    request_time   REAL            -- segundos que tardó la request
);

CREATE INDEX IF NOT EXISTS idx_requests_ts          ON requests (ts);
CREATE INDEX IF NOT EXISTS idx_requests_remote_addr ON requests (remote_addr);
CREATE INDEX IF NOT EXISTS idx_requests_path        ON requests (path);
CREATE INDEX IF NOT EXISTS idx_requests_method      ON requests (method);
CREATE INDEX IF NOT EXISTS idx_requests_headers_gin ON requests USING gin (headers);
