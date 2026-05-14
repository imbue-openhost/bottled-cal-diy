FROM calcom/cal.com:latest

USER root

# The calcom/cal.com image is based on node:18-slim (Debian).
# Install PostgreSQL, Redis, Python3, and tini for process supervision.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        postgresql \
        postgresql-client \
        redis-server \
        nginx \
        tini \
        ca-certificates \
        procps \
        curl \
        openssl \
        locales \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh        /opt/openhost/start.sh
COPY auth_proxy.py   /opt/openhost/auth_proxy.py
COPY bootstrap_admin.py /opt/openhost/bootstrap_admin.py
COPY nginx.conf      /opt/openhost/nginx.conf

RUN chmod 0755 /opt/openhost/start.sh \
               /opt/openhost/auth_proxy.py \
               /opt/openhost/bootstrap_admin.py

EXPOSE 8080

ENTRYPOINT ["tini", "--", "/opt/openhost/start.sh"]
