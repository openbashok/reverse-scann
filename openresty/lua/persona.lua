-- persona.lua — identidad activa del honeypot.
-- Lee el perfil activo desde Postgres a un shared dict (refrescado por un timer)
-- y con él decide el header Server, los headers extra y las respuestas por ruta.
-- Siempre hay exactamente una persona vigente: nunca dos en paralelo.

local cjson = require "cjson.safe"

local _M = {}

local DB = {
    host     = os.getenv("DB_HOST") or "db",
    port     = tonumber(os.getenv("DB_PORT")) or 5432,
    database = os.getenv("DB_NAME") or "honeypot",
    user     = os.getenv("DB_USER") or "honeypot",
    password = os.getenv("DB_PASS") or "honeypot_dev_pass",
}

local POLL_INTERVAL = 4  -- segundos entre refrescos del perfil activo

-- Fallback cableado: si no hay DB ni perfil activo, el honeypot igual responde
-- como un Apache creíble y no se cae.
local DEFAULT = {
    server_header   = "Apache/2.4.41 (Ubuntu)",
    index_status    = 200,
    index_body      = "<html><body><h1>It works!</h1></body></html>",
    notfound_status = 404,
    notfound_body   = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        .. "<html><head><title>404 Not Found</title></head><body>\n"
        .. "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>\n"
        .. "<hr><address>Apache/2.4.41 (Ubuntu) Server Port 80</address></body></html>",
    extra_headers   = {},
    routes          = {},
}

-- Quita CR/LF y bytes de control de un valor de header: defensa contra
-- header/response splitting aunque la config venga adulterada en la DB.
local function clean_header(v)
    if type(v) ~= "string" then
        v = tostring(v)
    end
    return (string.gsub(v, "[%z\1-\31\127]", ""))
end

local function shared()
    return ngx.shared.persona
end

-- Perfil vigente (desde el shared dict, con fallback al DEFAULT).
local function active()
    local raw = shared():get("active")
    if raw then
        local p = cjson.decode(raw)
        if type(p) == "table" then
            return p
        end
    end
    return DEFAULT
end

-- ---- carga desde Postgres -------------------------------------------------

local function load_from_db()
    local pgmoon = require "pgmoon"
    local pg = pgmoon.new(DB)
    pg:settimeout(4000)

    local ok, err = pg:connect()
    if not ok then
        return nil, "connect: " .. (err or "?")
    end

    -- Firma barata (id + updated_at del perfil activo): si no cambió, no recargamos
    -- ni re-serializamos el perfil (que puede ser grande). Cubre edición y cambio de activo.
    local sig_res = pg:query(
        "SELECT (id || '-' || extract(epoch from updated_at))::text AS sig "
        .. "FROM profiles WHERE is_active LIMIT 1")
    local sig = (sig_res and sig_res[1] and sig_res[1].sig) or "none"
    if shared():get("sig") == sig then
        pg:keepalive(10000, 2)
        return true
    end
    if sig == "none" then
        shared():delete("active")
        shared():set("sig", "none")
        pg:keepalive(10000, 2)
        return nil, "no active profile"
    end

    -- jsonb casteado a texto: lo decodificamos nosotros con cjson
    local res, qerr = pg:query([[
        SELECT server_header, index_status, index_body,
               notfound_status, notfound_body,
               extra_headers::text AS extra_headers,
               routes::text        AS routes
        FROM profiles WHERE is_active LIMIT 1]])
    pg:keepalive(10000, 2)

    if not res then
        return nil, "query: " .. (qerr or "?")
    end
    local row = res[1]
    if not row then
        return nil, "no active profile"
    end

    local profile = {
        server_header   = row.server_header or DEFAULT.server_header,
        index_status    = tonumber(row.index_status) or 200,
        index_body      = row.index_body or "",
        notfound_status = tonumber(row.notfound_status) or 404,
        notfound_body   = row.notfound_body or "",
        extra_headers   = cjson.decode(row.extra_headers or "{}") or {},
        routes          = cjson.decode(row.routes or "[]") or {},
    }

    shared():set("active", cjson.encode(profile))
    shared():set("sig", sig)
    return true
end

function _M._refresh(premature)
    if premature then
        return
    end
    local ok, err = pcall(load_from_db)
    if not ok then
        ngx.log(ngx.ERR, "persona: refresh fallo: ", err)
    elseif err then
        ngx.log(ngx.WARN, "persona: ", err)
    end
    local okt, terr = ngx.timer.at(POLL_INTERVAL, _M._refresh)
    if not okt then
        ngx.log(ngx.ERR, "persona: no pude reprogramar timer: ", terr or "?")
    end
end

-- Arranca el poller una sola vez (worker 0); el shared dict lo comparten todos.
function _M.init()
    if ngx.worker.id() == 0 then
        local ok, err = ngx.timer.at(0, _M._refresh)
        if not ok then
            ngx.log(ngx.ERR, "persona: no pude arrancar poller: ", err or "?")
        end
    end
end

-- ---- aplicación por request -----------------------------------------------

-- header_filter: Server + headers extra globales (se aplican a toda respuesta).
function _M.set_headers()
    local p = active()
    ngx.header["Server"] = clean_header(p.server_header)
    if type(p.extra_headers) == "table" then
        for k, v in pairs(p.extra_headers) do
            ngx.header[clean_header(k)] = clean_header(v)
        end
    end
end

local function route_matches(r, uri)
    local m = r.match or ""
    local t = r.match_type or "prefix"
    if t == "exact" then
        return uri == m
    elseif t == "pattern" then
        local ok, found = pcall(string.find, uri, m)
        return ok and found ~= nil
    else -- prefix
        return string.sub(uri, 1, #m) == m
    end
end

-- content handler: elige la respuesta según el perfil activo.
-- Importante: NO refleja ninguna entrada del atacante en el cuerpo; solo sirve
-- contenido estático definido por nosotros en la config, así no hay XSS reflejado.
function _M.serve()
    local p = active()
    local uri = ngx.var.uri or "/"
    local is_head = (ngx.var.request_method == "HEAD")

    if type(p.routes) == "table" then
        for _, r in ipairs(p.routes) do
            if type(r) == "table" and route_matches(r, uri) then
                ngx.status = tonumber(r.status) or 200
                ngx.header["Content-Type"] = clean_header(r.content_type or "text/html")
                if type(r.headers) == "table" then
                    for k, v in pairs(r.headers) do
                        ngx.header[clean_header(k)] = clean_header(v)
                    end
                end
                if not is_head and r.body then
                    ngx.print(r.body)
                end
                return ngx.exit(ngx.status)
            end
        end
    end

    if uri == "/" or uri == "/index.html" then
        ngx.status = tonumber(p.index_status) or 200
        ngx.header["Content-Type"] = "text/html"
        if not is_head and p.index_body then
            ngx.print(p.index_body)
        end
        return ngx.exit(ngx.status)
    end

    ngx.status = tonumber(p.notfound_status) or 404
    ngx.header["Content-Type"] = "text/html"
    if not is_head and p.notfound_body then
        ngx.print(p.notfound_body)
    end
    return ngx.exit(ngx.status)
end

return _M
