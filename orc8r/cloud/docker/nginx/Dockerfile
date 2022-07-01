FROM debian:11 as build
ENV DEBIAN_FRONTEND "noninteractive"

RUN apt update 
RUN apt install -y build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev git wget

RUN addgroup --system  nginx 
RUN adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos "nginx user" --shell /bin/false  nginx 
RUN mkdir -p /var/cache/nginx/
RUN mkdir -p /usr/lib/nginx/modules/

# === Build Nginx ===

WORKDIR /nginx_build/
RUN wget http://nginx.org/download/nginx-1.21.6.tar.gz
RUN tar -zxvf nginx-1.21.6.tar.gz
RUN wget https://github.com/nicholaschiasson/ngx_upstream_jdomain/archive/refs/tags/1.4.0.tar.gz
RUN tar -zxvf 1.4.0.tar.gz
RUN git clone -b 1.21.6 https://github.com/nginxinc/docker-nginx.git

WORKDIR /nginx_build/nginx-1.21.6/
RUN ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx \
    --group=nginx \
    --with-compat \
    --with-file-aio \
    --with-threads  \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-1.21.6/debian/debuild-base/nginx-1.21.6=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
    --add-module=/nginx_build/ngx_upstream_jdomain-1.4.0/

RUN make 
RUN make install

RUN rm /etc/nginx/*.default
RUN rm /etc/nginx/fastcgi.conf

# === Nginx Docker ===

RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

RUN cp /nginx_build/docker-nginx/entrypoint/docker-entrypoint.sh /
RUN mkdir /docker-entrypoint.d
RUN cp /nginx_build/docker-nginx/entrypoint/10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
RUN cp /nginx_build/docker-nginx/entrypoint/20-envsubst-on-templates.sh /docker-entrypoint.d
RUN cp /nginx_build/docker-nginx/entrypoint/30-tune-worker-processes.sh /docker-entrypoint.d

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

STOPSIGNAL SIGQUIT

# === Magma ====

RUN apt-get update && \
  apt-get install -y python3-pip daemontools
RUN pip3 install --no-cache-dir PyYAML jinja2

RUN mkdir -p /var/opt/magma/envdir
COPY configs /etc/magma/configs

WORKDIR /tmp

ARG NGINX_FILES=src/magma/orc8r/cloud/docker/nginx

COPY ${NGINX_FILES}/templates /etc/magma/templates
COPY ${NGINX_FILES}/generate_nginx_configs.py /usr/local/bin/generate_nginx_configs.py
COPY ${NGINX_FILES}/create_test_proxy_certs /usr/local/bin/create_test_proxy_certs

CMD /usr/local/bin/create_test_proxy_certs && envdir /var/opt/magma/envdir /usr/local/bin/generate_nginx_configs.py && exec nginx -g 'daemon off;'
