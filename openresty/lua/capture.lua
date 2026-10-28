-- capture.lua — captura cada request HTTP completa y la inserta en PostgreSQL.
-- Si la base no está disponible, cae a un JSONL en /data/captures para no perder nada.

local cjson = require "cjson.safe"
cjson.encode_escape_forward_slash(false)

local _M = {}

local DB = {
    host     = os.getenv("DB_HOST") or "db",
    port     = tonumber(os.getenv("DB_PORT")) or 5432,
    database = os.getenv("DB_NAME") or "honeypot",
    user     = os.getenv("DB_USER") or "honeypot",
    password = os.getenv("DB_PASS") or "honeypot_dev_pass",
}

local MAX_BODY = tonumber(os.getenv("CAPTURE_MAX_BODY")) or 262144

-- Fase access: lo único que no se puede hacer en la fase log es leer el body.
function _M.read_request()
    ngx.req.read_body()
end

-- Devuelve body, encoding, tamaño real y si quedó truncado.
local function get_body()
    local data = ngx.req.get_body_data()
    local size

    if data then
        size = #data
    else
        -- Body grande: nginx lo volcó a un archivo temporal
        local path = ngx.req.get_body_file()
        if not path then
            return nil, nil, 0, false
        end
        local f = io.open(path, "rb")
        if not f then
            return nil, nil, 0, false
        end
        size = f:seek("end")
        f:seek("set", 0)
        data = f:read(MAX_BODY)
        f:close()
        if not data then
            return nil, nil, size or 0, false
        end
    end

    local truncated = false
    if #data > MAX_BODY then
        data = string.sub(data, 1, MAX_BODY)
        truncated = true
    elseif size > #data then
        truncated = true
    end

    -- Si tiene bytes de control / binarios, lo guardamos en base64
    if string.find(data, "[%z\1-\8\11\12\14-\31]") then
        return ngx.encode_base64(data), "base64", size, truncated
    end
    return data, "utf8", size, truncated
end

-- NULL-safe escape para armar el INSERT
local function lit(pg, v)
    if v == nil or v == cjson.null then
        return "NULL"
    end
    return pg:escape_literal(tostring(v))
end

local function write_fallback(record)
    local line = cjson.encode(record)
    if not line then
        return
    end
    local fname = "/data/captures/fallback-" .. os.date("!%Y-%m-%d") .. ".jsonl"
    local f = io.open(fname, "a")
    if f then
        f:write(line, "\n")
        f:close()
    end
end

local function do_insert(record)
    local pgmoon = require "pgmoon"
    local pg = pgmoon.new(DB)
    pg:settimeout(5000)

    local ok, err = pg:connect()
    if not ok then
        ngx.log(ngx.ERR, "honeypot: sin conexion a postgres: ", err or "?")
        write_fallback(record)
        return
    end

    local headers_json = cjson.encode(record.headers) or "{}"

    local sql = string.format([[
        INSERT INTO requests
            (ts, remote_addr, remote_port, scheme, host, method, uri, path, query,
             http_version, user_agent, headers, raw_header, body, body_encoding,
             body_size, body_truncated, status, request_time)
        VALUES
            (to_timestamp(%s), %s::inet, %s, %s, %s, %s, %s, %s, %s,
             %s, %s, %s::jsonb, %s, %s, %s,
             %s, %s, %s, %s)]],
        tostring(record.ts),
        lit(pg, record.remote_addr),
        tostring(record.remote_port or "NULL"),
        lit(pg, record.scheme),
        lit(pg, record.host),
        lit(pg, record.method),
        lit(pg, record.uri),
        lit(pg, record.path),
        lit(pg, record.query),
        lit(pg, record.http_version),
        lit(pg, record.user_agent),
        pg:escape_literal(headers_json),
        lit(pg, record.raw_header),
        lit(pg, record.body),
        lit(pg, record.body_encoding),
        tostring(record.body_size or 0),
        record.body_truncated and "true" or "false",
        tostring(record.status or "NULL"),
        tostring(record.request_time or "NULL")
    )

    local res, qerr = pg:query(sql)
    if not res then
        ngx.log(ngx.ERR, "honeypot: fallo el INSERT: ", qerr or "?")
        write_fallback(record)
        pg:disconnect()
        return
    end

    pg:keepalive(10000, 5)
end

-- Corre en un timer (fuera del ciclo de la request): acá sí hay cosockets.
-- Cualquier excepción no prevista termina en el fallback, nunca se pierde el registro.
local function insert_record(premature, record)
    if premature then
        write_fallback(record)
        return
    end
    local ok, err = pcall(do_insert, record)
    if not ok then
        ngx.log(ngx.ERR, "honeypot: excepcion insertando: ", err or "?")
        write_fallback(record)
    end
end

-- Fase log: arma el registro y lo despacha a un timer para insertarlo.
function _M.log_request()
    local body, body_enc, body_size, body_trunc = get_body()

    local raw_header
    local ok, raw = pcall(ngx.req.raw_header, false)
    if ok then
        raw_header = raw
    end

    -- El redirect interno de error_page cambia el método a GET, pero $request
    -- conserva la request line original tal cual la mandó el cliente.
    local req_line = ngx.var.request or ""
    local method, line_uri, httpver = string.match(req_line, "^(%S+)%s+(%S+)%s+HTTP/(%S+)%s*$")
    method = method or ngx.req.get_method()
    httpver = httpver or tostring(ngx.req.http_version() or "")

    -- request_uri es la URI original (sobrevive a los redirects internos de error_page).
    -- En requests rechazadas (400) puede venir vacía: usamos la de la request line.
    local request_uri = ngx.var.request_uri
    if not request_uri or request_uri == "" then
        request_uri = line_uri or ""
    end
    local path, query = request_uri, nil
    local qpos = string.find(request_uri, "?", 1, true)
    if qpos then
        path = string.sub(request_uri, 1, qpos - 1)
        query = string.sub(request_uri, qpos + 1)
    end

    local record = {
        ts             = ngx.now(),
        remote_addr    = ngx.var.remote_addr,
        remote_port    = tonumber(ngx.var.remote_port),
        scheme         = ngx.var.scheme,
        host           = ngx.var.host,
        method         = method,
        uri            = request_uri,
        path           = path,
        query          = query,
        http_version   = httpver,
        user_agent     = ngx.var.http_user_agent,
        -- claves en minúscula para consultas JSONB consistentes;
        -- el casing original queda preservado en raw_header
        headers        = ngx.req.get_headers(100),
        raw_header     = raw_header,
        body           = body,
        body_encoding  = body_enc,
        body_size      = body_size,
        body_truncated = body_trunc,
        status         = ngx.status,
        request_time   = tonumber(ngx.var.request_time),
    }

    local tok, terr = ngx.timer.at(0, insert_record, record)
    if not tok then
        ngx.log(ngx.ERR, "honeypot: no pude crear timer: ", terr or "?")
        write_fallback(record)
    end
end

return _M
