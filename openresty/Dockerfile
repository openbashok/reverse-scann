FROM openresty/openresty:1.25.3.2-alpine-fat

RUN apk add --no-cache openssl \
    && opm get leafo/pgmoon fffonion/lua-resty-openssl

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /data/captures /certs

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
