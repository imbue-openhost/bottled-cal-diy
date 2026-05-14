#!/usr/bin/env python3
"""OpenHost SSO sidecar for cal.diy (Pattern B2 — direct DB session injection).

Runs on 127.0.0.1:8090. nginx calls this via auth_request for owner
HTML navigations. When the owner has no cal.com session cookie, this
sidecar INSERTs a session row directly into the NextAuth Session table
and returns Set-Cookie headers.
"""

import http.server
import json
import os
import secrets
import subprocess
import sys
import time
import uuid

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8090
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")
DB_HOST = "127.0.0.1"
DB_PORT = "5432"
DB_USER = os.environ.get("DB_USER", "calcom")
DB_NAME = os.environ.get("DB_NAME", "calendso")

SESSION_COOKIE = "__Secure-next-auth.session-token"
SESSION_EXPIRY_DAYS = 30

def log(msg):
    print(f"[openhost:sso] {msg}", file=sys.stderr, flush=True)


def run_sql(sql):
    try:
        pg_bin = os.environ.get("PG_BINDIR", "/usr/lib/postgresql/15/bin")
        result = subprocess.run(
            [f"{pg_bin}/psql", "-h", DB_HOST, "-p", DB_PORT, "-U", DB_USER, "-d", DB_NAME, "-tAX", "-c", sql],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception as e:
        log(f"SQL error: {e}")
        return ""


def get_admin_user_id():
    result = run_sql("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1")
    return int(result) if result and result.isdigit() else None


def create_session(user_id):
    session_token = str(uuid.uuid4())
    session_id = str(uuid.uuid4())[:25]
    expires = f"NOW() + INTERVAL '{SESSION_EXPIRY_DAYS} days'"
    sql = f"""INSERT INTO "Session" (id, "sessionToken", "userId", expires) VALUES ('{session_id}', '{session_token}', {user_id}, {expires}) RETURNING "sessionToken";"""
    result = run_sql(sql)
    return result if result else session_token


class SSOHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/_openhost/auth_check"):
            is_owner = self.headers.get("X-OpenHost-Is-Owner", "").lower() == "true"
            cookies = self.headers.get("Cookie", "")
            has_session = SESSION_COOKIE in cookies

            if is_owner and not has_session:
                self.send_response(401)
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        elif self.path.startswith("/_openhost/login"):
            user_id = get_admin_user_id()
            if user_id is None:
                self.send_response(503)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Admin user not yet created")
                return

            session_token = create_session(user_id)
            redirect_to = "/"

            self.send_response(302)
            cookie_val = f"{SESSION_COOKIE}={session_token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_EXPIRY_DAYS * 86400}"
            self.send_header("Set-Cookie", cookie_val)
            self.send_header("Location", redirect_to)
            self.end_headers()
            log(f"SSO login: created session for user {user_id}")

        else:
            self.send_response(404)
            self.end_headers()


def main():
    server = http.server.HTTPServer((LISTEN_HOST, LISTEN_PORT), SSOHandler)
    log(f"SSO sidecar listening on {LISTEN_HOST}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
