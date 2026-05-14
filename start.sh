#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# OpenHost supervisor for Cal.diy (cal.com)
#
# Manages: PostgreSQL, Redis, cal.com (Next.js), bootstrap, auth_proxy
# ---------------------------------------------------------------------------

APP_DATA="${OPENHOST_APP_DATA_DIR:-/data/app_data/cal-diy}"
APP_TEMP="${OPENHOST_APP_TEMP_DIR:-/data/app_temp_data/cal-diy}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"

PGDATA="${APP_DATA}/pgdata"
PGRUN="/var/run/postgresql"
SECRETS_FILE="${APP_DATA}/.secrets"
DB_NAME="calendso"
DB_USER="calcom"
DB_PASS="calcom_local"

LOG_PREFIX="[openhost:start]"

log() { echo "${LOG_PREFIX} $*"; }
die() { log "FATAL: $*"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Ensure directories
# ---------------------------------------------------------------------------
mkdir -p "${APP_DATA}" "${APP_TEMP}" "${PGRUN}"
chown postgres:postgres "${PGRUN}" "${APP_TEMP}"

PG_BINDIR=$(find /usr/lib/postgresql -name initdb -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
[ -z "$PG_BINDIR" ] && die "Cannot find PostgreSQL binaries"

pgsu() { su postgres -s /bin/bash -c "export PATH='${PG_BINDIR}:\$PATH'; $*"; }

log "Starting auth proxy on 0.0.0.0:8080 (early, for healthcheck)..."
python3 /opt/openhost/auth_proxy.py &
PROXY_PID=$!

# ---------------------------------------------------------------------------
# 2. PostgreSQL setup
# ---------------------------------------------------------------------------
if [ ! -f "${PGDATA}/PG_VERSION" ]; then
    log "Initialising PostgreSQL data directory..."
    mkdir -p "${PGDATA}"
    chown -R postgres:postgres "${PGDATA}"
    pgsu "initdb -D '${PGDATA}' --auth=trust --no-locale --encoding=UTF8" \
        || die "initdb failed"

    # Listen only on localhost
    cat >> "${PGDATA}/postgresql.conf" <<PGEOF
listen_addresses = '127.0.0.1'
port = 5432
unix_socket_directories = '${PGRUN}'
shared_buffers = 128MB
work_mem = 8MB
max_connections = 50
PGEOF
    # Trust local connections
    cat > "${PGDATA}/pg_hba.conf" <<HBAEOF
local   all   all                 trust
host    all   all   127.0.0.1/32  trust
HBAEOF
else
    log "Existing PostgreSQL data directory found."
    chown -R postgres:postgres "${PGDATA}"
fi

log "Starting PostgreSQL..."
pgsu "pg_ctl -D '${PGDATA}' -l '${APP_TEMP}/postgresql.log' -o '-k ${PGRUN}' start" \
    || die "pg_ctl start failed"

# Wait for pg to be ready
for i in $(seq 1 30); do
    if pgsu "pg_isready -h 127.0.0.1 -p 5432" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
pgsu "pg_isready -h 127.0.0.1 -p 5432" || die "PostgreSQL did not become ready"
log "PostgreSQL is ready."

# Create role and database if needed
pgsu "psql -h 127.0.0.1 -p 5432 -tc \"SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'\"" \
    | grep -q 1 || {
    log "Creating database role '${DB_USER}'..."
    pgsu "psql -h 127.0.0.1 -p 5432 -c \"CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}' SUPERUSER;\""
}

pgsu "psql -h 127.0.0.1 -p 5432 -tc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\"" \
    | grep -q 1 || {
    log "Creating database '${DB_NAME}'..."
    pgsu "psql -h 127.0.0.1 -p 5432 -c \"CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};\""
}

# ---------------------------------------------------------------------------
# 3. Redis
# ---------------------------------------------------------------------------
log "Starting Redis..."
redis-server --daemonize yes \
    --bind 127.0.0.1 \
    --port 6379 \
    --dir "${APP_TEMP}" \
    --loglevel warning \
    --save "" \
    || die "Redis start failed"

for i in $(seq 1 15); do
    redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG && break
    sleep 1
done
redis-cli -h 127.0.0.1 -p 6379 ping | grep -q PONG || die "Redis did not become ready"
log "Redis is ready."

# ---------------------------------------------------------------------------
# 4. Generate / load stable secrets
# ---------------------------------------------------------------------------
if [ -f "${SECRETS_FILE}" ]; then
    log "Loading existing secrets..."
    # shellcheck disable=SC1090
    source "${SECRETS_FILE}"
else
    log "Generating new secrets..."
    NEXTAUTH_SECRET="$(openssl rand -hex 32)"
    CALENDSO_ENCRYPTION_KEY="$(openssl rand -hex 16)"
    cat > "${SECRETS_FILE}" <<EOF
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET}"
export CALENDSO_ENCRYPTION_KEY="${CALENDSO_ENCRYPTION_KEY}"
EOF
    chmod 0600 "${SECRETS_FILE}"
fi

# ---------------------------------------------------------------------------
# 5. Environment variables for cal.com
# ---------------------------------------------------------------------------
export DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}"
export DATABASE_DIRECT_URL="${DATABASE_URL}"
export NEXT_PUBLIC_WEBAPP_URL="https://cal-diy.${ZONE_DOMAIN}"
export NEXTAUTH_URL="https://cal-diy.${ZONE_DOMAIN}"
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET}"
export CALENDSO_ENCRYPTION_KEY="${CALENDSO_ENCRYPTION_KEY}"
export NODE_ENV="production"
export CALCOM_TELEMETRY_DISABLED="1"
export NEXT_PUBLIC_DISABLE_SIGNUP="true"
export NEXT_PUBLIC_LICENSE_CONSENT="agree"
# Redis is optional for cal.com but beneficial for caching
export REDIS_URL="redis://127.0.0.1:6379"
# Trust the proxy headers
export NODE_TLS_REJECT_UNAUTHORIZED="0"

# Persist DATABASE_URL for bootstrap/auth_proxy
export CALCOM_DB_URL="${DATABASE_URL}"

log "NEXT_PUBLIC_WEBAPP_URL=${NEXT_PUBLIC_WEBAPP_URL}"
log "DATABASE_URL=postgresql://${DB_USER}:***@127.0.0.1:5432/${DB_NAME}"

# ---------------------------------------------------------------------------
# 6. Start cal.com via upstream start script
# ---------------------------------------------------------------------------
CALCOM_START="/calcom/scripts/start.sh"
if [ ! -x "${CALCOM_START}" ]; then
    # Fallback: some image versions don't have the start script
    # In that case run prisma migrate + next start directly
    CALCOM_START=""
fi

CALCOM_PID=""
if [ -n "${CALCOM_START}" ]; then
    log "Starting cal.com via upstream start script..."
    (
        cd /calcom
        exec bash "${CALCOM_START}"
    ) &
    CALCOM_PID=$!
else
    log "Starting cal.com directly (no upstream start script found)..."
    (
        cd /calcom
        # Run Prisma migrations
        npx prisma migrate deploy --schema /calcom/packages/prisma/schema.prisma 2>&1 || true
        npx prisma db seed --schema /calcom/packages/prisma/schema.prisma 2>&1 || true
        # Start the Next.js app
        exec node /calcom/apps/web/server.js
    ) &
    CALCOM_PID=$!
fi
log "Cal.com PID: ${CALCOM_PID}"

# ---------------------------------------------------------------------------
# 7. Wait for cal.com to be responsive, then bootstrap admin
# ---------------------------------------------------------------------------
log "Waiting for cal.com to become responsive on :3000..."
for i in $(seq 1 120); do
    if curl -sf -o /dev/null "http://127.0.0.1:3000/" 2>/dev/null; then
        break
    fi
    # Check that cal.com process is still alive
    if ! kill -0 "${CALCOM_PID}" 2>/dev/null; then
        log "WARNING: cal.com process exited early, continuing anyway..."
        break
    fi
    sleep 2
done
log "Cal.com responded (or timeout reached). Running bootstrap..."

python3 /opt/openhost/bootstrap_admin.py
log "Bootstrap complete."

# ---------------------------------------------------------------------------
# 9. Supervise all processes
# ---------------------------------------------------------------------------
log "All services started. Supervising..."

# Monitor all child processes
while true; do
    # Check auth proxy
    if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
        log "Auth proxy exited unexpectedly. Restarting..."
        python3 /opt/openhost/auth_proxy.py &
        PROXY_PID=$!
        log "Auth proxy restarted, PID: ${PROXY_PID}"
    fi

    # Check cal.com
    if [ -n "${CALCOM_PID}" ] && ! kill -0 "${CALCOM_PID}" 2>/dev/null; then
        log "Cal.com process exited. Restarting..."
        if [ -n "${CALCOM_START}" ]; then
            ( cd /calcom && exec bash "${CALCOM_START}" ) &
        else
            ( cd /calcom && exec node /calcom/apps/web/server.js ) &
        fi
        CALCOM_PID=$!
        log "Cal.com restarted, PID: ${CALCOM_PID}"
    fi

    # Check PostgreSQL
    if ! pgsu "pg_isready -h 127.0.0.1 -p 5432" >/dev/null 2>&1; then
        log "PostgreSQL appears down. Attempting restart..."
        pgsu "pg_ctl -D '${PGDATA}' -l '${APP_TEMP}/postgresql.log' -o '-k ${PGRUN}' start" || true
    fi

    # Check Redis
    if ! redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG; then
        log "Redis appears down. Restarting..."
        redis-server --daemonize yes --bind 127.0.0.1 --port 6379 --dir "${APP_TEMP}" --loglevel warning --save "" || true
    fi

    sleep 5
done
