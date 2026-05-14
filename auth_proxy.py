#!/usr/bin/env python3
"""
auth_proxy.py - Pattern B2 auth proxy for Cal.diy

Listens on 0.0.0.0:8080, proxies to cal.com on 127.0.0.1:3000.

SSO flow (Pattern B2 - direct DB session injection):
  1. Owner visits a dashboard path without a session cookie.
  2. Proxy generates a UUID session token.
  3. Proxy INSERTs a row into the "Session" table linked to the admin user.
  4. Proxy sets the next-auth.session-token cookie and 302 redirects.

Public paths (booking pages, etc.) pass through without auto-login.
Dashboard paths trigger auto-login for the owner only.

Cal.com NextAuth session cookie names:
  - "next-auth.session-token" (HTTP)
  - "__Secure-next-auth.session-token" (HTTPS, when X-Forwarded-Proto: https)

We use the __Secure- variant since OpenHost serves over HTTPS.
"""

import http.client
import http.server
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse, urlencode

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 3000

DB_HOST = "127.0.0.1"
DB_PORT = "5432"
DB_NAME = "calendso"
DB_USER = "calcom"

ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")
APP_DATA = os.environ.get("OPENHOST_APP_DATA_DIR", "/data/app_data/cal-diy")
BOOTSTRAP_MARKER = os.path.join(APP_DATA, ".bootstrap_done")

# Session cookie names
COOKIE_NAME_SECURE = "__Secure-next-auth.session-token"
COOKIE_NAME_PLAIN = "next-auth.session-token"

# Session duration: 30 days (matches NextAuth default)
SESSION_DURATION_DAYS = 30

# Dashboard paths that trigger auto-login for the owner.
# Everything else is considered public (booking pages, user profiles, etc.)
DASHBOARD_PREFIXES = (
    "/settings",
    "/event-types",
    "/availability",
    "/apps",
    "/workflows",
    "/getting-started",
    "/bookings",
    "/teams",
    "/video",
    "/auth",
    "/api/auth",
)

# Headers from OpenHost router that should be stripped before forwarding
OPENHOST_INTERNAL_HEADERS = [
    "x-openhost-is-owner",
    "x-openhost-app-token",
    "x-openhost-zone-domain",
    "x-openhost-user-email",
]


def log(msg: str) -> None:
    print(f"[openhost:auth_proxy] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def run_sql(sql: str) -> str:
    """Execute SQL via psql and return stdout."""
    try:
        result = subprocess.run(
            [
                "psql",
                "-h", DB_HOST,
                "-p", DB_PORT,
                "-U", DB_USER,
                "-d", DB_NAME,
                "-tAc", sql,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            log(f"SQL error: {result.stderr.strip()}")
            return ""
        return result.stdout.strip()
    except Exception as e:
        log(f"SQL exception: {e}")
        return ""


def get_admin_user_id() -> str:
    """Get the admin user id from the bootstrap marker or database."""
    # Try marker file first (faster)
    try:
        with open(BOOTSTRAP_MARKER, "r") as f:
            uid = f.read().strip()
            if uid:
                return uid
    except FileNotFoundError:
        pass

    # Fall back to database query
    admin_email = f"admin@{ZONE_DOMAIN}"
    uid = run_sql(f"SELECT id FROM users WHERE email = '{admin_email}' LIMIT 1")
    return uid


def create_session(user_id: str) -> tuple:
    """
    Create a session in the NextAuth Session table.

    Returns (session_token, expires) or (None, None) on failure.

    Cal.com Prisma schema for Session:
      model Session {
        id           String   @id @default(cuid())
        sessionToken String   @unique
        userId       Int
        expires      DateTime
      }
    """
    session_token = str(uuid.uuid4())
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DURATION_DAYS)
    expires_str = expires.strftime("%Y-%m-%d %H:%M:%S+00")

    # Generate a cuid-like id (simple version: just use a random string)
    session_id = "cl" + uuid.uuid4().hex[:24]

    sql = f"""
    INSERT INTO "Session" (id, "sessionToken", "userId", expires)
    VALUES ('{session_id}', '{session_token}', {user_id}, '{expires_str}')
    ON CONFLICT ("sessionToken") DO NOTHING
    RETURNING "sessionToken";
    """

    result = run_sql(sql)
    if result:
        log(f"Created session for user {user_id}, expires {expires_str}")
        return session_token, expires
    else:
        log(f"Failed to create session for user {user_id}")
        return None, None


def cleanup_expired_sessions() -> None:
    """Remove expired sessions (housekeeping)."""
    run_sql("""DELETE FROM "Session" WHERE expires < NOW()""")


# ---------------------------------------------------------------------------
# HTTP Proxy Handler
# ---------------------------------------------------------------------------

class AuthProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that proxies to cal.com with Pattern B2 SSO."""

    # Suppress default access log
    def log_message(self, format, *args):
        pass

    def _is_owner(self) -> bool:
        """Check if the request is from the OpenHost owner."""
        return self.headers.get("X-OpenHost-Is-Owner", "").lower() == "true"

    def _has_session_cookie(self) -> bool:
        """Check if the request has a NextAuth session cookie."""
        cookie_header = self.headers.get("Cookie", "")
        return (
            COOKIE_NAME_SECURE in cookie_header
            or COOKIE_NAME_PLAIN in cookie_header
        )

    def _is_html_navigation(self) -> bool:
        """Check if the request is an HTML page navigation (not API/asset)."""
        accept = self.headers.get("Accept", "")
        return "text/html" in accept

    def _is_dashboard_path(self) -> bool:
        """Check if the path is a dashboard path that requires auth."""
        path = self.path.split("?")[0]  # Strip query string
        return path.startswith(DASHBOARD_PREFIXES)

    def _maybe_auto_login(self) -> bool:
        """
        Attempt to auto-login the owner by creating a DB session.
        Returns True if a redirect was sent, False otherwise.
        """
        user_id = get_admin_user_id()
        if not user_id:
            log("Cannot auto-login: admin user not found in database.")
            return False

        session_token, expires = create_session(user_id)
        if not session_token:
            log("Cannot auto-login: session creation failed.")
            return False

        # Determine cookie name based on protocol
        # OpenHost always terminates TLS, so use the secure cookie
        cookie_name = COOKIE_NAME_SECURE

        # Format expiry for Set-Cookie
        expires_str = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")

        # Build the redirect URL (same as the original request)
        host = self.headers.get("X-Forwarded-Host", self.headers.get("Host", f"cal-diy.{ZONE_DOMAIN}"))
        redirect_url = f"https://{host}{self.path}"

        # Send redirect with session cookie
        self.send_response(302)
        cookie_value = (
            f"{cookie_name}={session_token}; "
            f"Path=/; "
            f"HttpOnly; "
            f"Secure; "
            f"SameSite=Lax; "
            f"Expires={expires_str}"
        )
        self.send_header("Set-Cookie", cookie_value)
        self.send_header("Location", redirect_url)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()

        log(f"Auto-login redirect for owner to {self.path}")
        return True

    def _proxy_request(self, method: str, body: bytes = None) -> None:
        """Forward the request to the upstream cal.com server."""
        try:
            conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=25)

            # Build headers, stripping OpenHost internal ones
            headers = {}
            for key, value in self.headers.items():
                if key.lower() not in OPENHOST_INTERNAL_HEADERS:
                    headers[key] = value

            # Set/override Host header from X-Forwarded-Host
            forwarded_host = self.headers.get("X-Forwarded-Host")
            if forwarded_host:
                headers["Host"] = forwarded_host

            # Ensure X-Forwarded-Proto is set (NextAuth needs this)
            headers["X-Forwarded-Proto"] = "https"

            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()

            # Send response status
            self.send_response(resp.status)

            # Forward response headers
            for key, value in resp.getheaders():
                # Skip hop-by-hop headers
                if key.lower() in ("transfer-encoding",):
                    continue
                self.send_header(key, value)
            self.end_headers()

            # Forward response body in chunks
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

            conn.close()
        except Exception as e:
            log(f"Proxy error: {e}")
            try:
                body = b"<html><head><meta http-equiv='refresh' content='5'></head><body><p>Cal.diy is starting, please wait...</p></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass

    def _handle_request(self, method: str) -> None:
        """Main request handling logic."""
        path_no_qs = self.path.split("?")[0]

        # Health check endpoint
        if path_no_qs == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        # SSO auto-login check
        if (
            method == "GET"
            and self._is_owner()
            and not self._has_session_cookie()
            and self._is_html_navigation()
            and self._is_dashboard_path()
        ):
            if self._maybe_auto_login():
                return

        # Read body for POST/PUT/PATCH
        body = None
        content_length = self.headers.get("Content-Length")
        if content_length and method in ("POST", "PUT", "PATCH"):
            body = self.rfile.read(int(content_length))

        # Proxy the request
        self._proxy_request(method, body)

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_PATCH(self):
        self._handle_request("PATCH")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_HEAD(self):
        self._handle_request("HEAD")

    def do_OPTIONS(self):
        self._handle_request("OPTIONS")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log(f"Starting auth proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    log(f"Proxying to {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    log(f"Dashboard prefixes requiring auto-login: {DASHBOARD_PREFIXES}")

    # Periodic session cleanup (every ~100 requests via counter, or on startup)
    cleanup_expired_sessions()

    server = http.server.HTTPServer(
        (LISTEN_HOST, LISTEN_PORT),
        AuthProxyHandler,
    )
    server.timeout = 120

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down auth proxy.")
        server.shutdown()


if __name__ == "__main__":
    main()
