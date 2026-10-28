-- Perfiles de identidad ("personas") del honeypot.
-- El honeypot presenta SIEMPRE un único perfil activo: mostrar identidades
-- contradictorias en paralelo delataría que es un honeypot.

CREATE TABLE IF NOT EXISTS profiles (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    server_header   TEXT NOT NULL DEFAULT 'Apache/2.4.41 (Ubuntu)',
    index_status    INTEGER NOT NULL DEFAULT 200,
    index_body      TEXT,                              -- respuesta para "/"
    notfound_status INTEGER NOT NULL DEFAULT 404,
    notfound_body   TEXT,                              -- respuesta para paths sin ruta
    extra_headers   JSONB NOT NULL DEFAULT '{}'::jsonb, -- headers globales extra
    routes          JSONB NOT NULL DEFAULT '[]'::jsonb, -- [{match,match_type,status,content_type,headers,body}]
    is_active       BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Garantiza a nivel DB que haya como mucho UN perfil activo.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_profile_active
    ON profiles (is_active) WHERE is_active;

-- ---------------------------------------------------------------------------
-- Seed: tres identidades de ejemplo. apache-ubuntu arranca activo.
-- ---------------------------------------------------------------------------

INSERT INTO profiles (name, server_header, index_status, index_body, notfound_status, notfound_body, extra_headers, routes, is_active)
VALUES (
    'apache-ubuntu',
    'Apache/2.4.41 (Ubuntu)',
    200,
$idx$<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Apache2 Ubuntu Default Page: It works</title></head>
<body><div style="font-family:Verdana,sans-serif"><h1>Apache2 Ubuntu Default Page</h1>
<p>It works! This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
<p>You should <b>replace this file</b> (located at <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.</p>
</div></body></html>$idx$,
    404,
$nf$<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server Port 80</address></body></html>$nf$,
    '{}'::jsonb,
    '[]'::jsonb,
    true
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO profiles (name, server_header, index_status, index_body, notfound_status, notfound_body, extra_headers, routes, is_active)
VALUES (
    'nginx',
    'nginx/1.18.0 (Ubuntu)',
    200,
$idx$<!DOCTYPE html><html><head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p></body></html>$idx$,
    404,
$nf$<html><head><title>404 Not Found</title></head><body>
<center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>$nf$,
    '{}'::jsonb,
    '[]'::jsonb,
    false
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO profiles (name, server_header, index_status, index_body, notfound_status, notfound_body, extra_headers, routes, is_active)
VALUES (
    'wordpress-apache',
    'Apache/2.4.41 (Ubuntu)',
    200,
$idx$<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8">
<meta name="generator" content="WordPress 6.4.2" />
<title>My Blog &#8211; Just another WordPress site</title>
<link rel="https://api.w.org/" href="/wp-json/" /></head>
<body class="home blog wp-theme-twentytwentyfour"><h1>My Blog</h1>
<p>Just another WordPress site</p></body></html>$idx$,
    404,
$nf$<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8">
<title>Page not found &#8211; My Blog</title></head><body>
<h1>Oops! That page can&#8217;t be found.</h1></body></html>$nf$,
    '{"X-Powered-By": "PHP/7.4.33", "Link": "</wp-json/>; rel=\"https://api.w.org/\""}'::jsonb,
    $routes$[
      {"match": "/wp-login.php", "match_type": "exact", "status": 200, "content_type": "text/html; charset=UTF-8",
       "headers": {},
       "body": "<!DOCTYPE html><html><head><title>Log In &lsaquo; My Blog &#8212; WordPress</title></head><body class=\"login\"><div id=\"login\"><h1><a href=\"https://wordpress.org/\">My Blog</a></h1><form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\"><p><label>Username or Email Address<br/><input type=\"text\" name=\"log\" class=\"input\"/></label></p><p><label>Password<br/><input type=\"password\" name=\"pwd\" class=\"input\"/></label></p><p><input type=\"submit\" name=\"wp-submit\" value=\"Log In\"/></p></form></div></body></html>"},
      {"match": "/xmlrpc.php", "match_type": "exact", "status": 405, "content_type": "text/plain",
       "headers": {"Allow": "POST"},
       "body": "XML-RPC server accepts POST requests only."},
      {"match": "/wp-json", "match_type": "prefix", "status": 200, "content_type": "application/json; charset=UTF-8",
       "headers": {},
       "body": "{\"name\":\"My Blog\",\"description\":\"Just another WordPress site\",\"url\":\"http://localhost\",\"home\":\"http://localhost\",\"gmt_offset\":0,\"namespaces\":[\"oembed/1.0\",\"wp/v2\"]}"}
    ]$routes$::jsonb,
    false
)
ON CONFLICT (name) DO NOTHING;
