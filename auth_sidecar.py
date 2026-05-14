#!/usr/bin/env python3
"""OpenHost SSO sidecar for cal.diy (Pattern B1 — NextAuth credentials login).

Runs on 127.0.0.1:8090. When the owner visits without a session, this
sidecar logs in via NextAuth's credentials callback to mint a real
session, then redirects the browser with the session cookie.
"""

import http.client
import http.server
import json
import os
import re
import sys
import urllib.parse

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8090
CALCOM_HOST = "127.0.0.1"
CALCOM_PORT = 443
CALCOM_USE_SSL = True
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")
APP_HOST = f"cal-diy.{ZONE_DOMAIN}"

APP_DATA = os.environ.get("OPENHOST_APP_DATA_DIR", "/data/app_data/cal-diy")
CRED_FILE = os.path.join(APP_DATA, ".admin_credentials")


def _read_credentials():
    try:
        with open(CRED_FILE) as f:
            lines = f.read().strip().split("\n")
            return lines[0], lines[1]
    except (FileNotFoundError, IndexError):
        return f"admin@{ZONE_DOMAIN}", ""

SESSION_COOKIE_NAME = "__Secure-next-auth.session-token"


def log(msg):
    print(f"[openhost:sso] {msg}", file=sys.stderr, flush=True)


def _nextauth_login():
    email, password = _read_credentials()
    if not password:
        log("No admin credentials found yet")
        return []
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = http.client.HTTPSConnection(CALCOM_HOST, CALCOM_PORT, timeout=10, context=ctx)
        conn.request("GET", "/api/auth/csrf", headers={
            "Host": APP_HOST,
        })
        resp = conn.getresponse()
        csrf_body = resp.read().decode()
        log(f"CSRF response: {resp.status} body={csrf_body[:100]}")
        csrf_cookies = []
        for name, value in resp.getheaders():
            if name.lower() == "set-cookie":
                csrf_cookies.append(value.split(";")[0])
        csrf_data = json.loads(csrf_body)
        csrf_token = csrf_data.get("csrfToken", "")
        cookie_header = "; ".join(csrf_cookies)
        log(f"CSRF token: {csrf_token[:20]}... cookies: {len(csrf_cookies)}")

        form_data = urllib.parse.urlencode({
            "csrfToken": csrf_token,
            "email": email,
            "password": password,
            "redirect": "false",
            "json": "true",
            "callbackUrl": f"https://{APP_HOST}/",
        })

        conn2 = http.client.HTTPSConnection(CALCOM_HOST, CALCOM_PORT, timeout=10, context=ctx)
        conn2.request("POST", "/api/auth/callback/credentials", body=form_data, headers={
            "Host": APP_HOST,
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": cookie_header,
        })
        resp2 = conn2.getresponse()
        resp2_body = resp2.read().decode()
        log(f"Callback response: {resp2.status} body={resp2_body[:200]}")

        session_cookies = []
        for name, value in resp2.getheaders():
            if name.lower() == "set-cookie":
                if "session-token" in value:
                    secure_value = value
                    if not value.startswith("__Secure-"):
                        secure_value = value.replace(
                            "next-auth.session-token=",
                            "__Secure-next-auth.session-token="
                        )
                    if "; Secure" not in secure_value:
                        secure_value = secure_value.replace("; Path=", "; Secure; Path=")
                    session_cookies.append(secure_value)
        log(f"Session cookies found: {len(session_cookies)}")

        conn.close()
        conn2.close()
        return session_cookies

    except Exception as e:
        import traceback
        log(f"Login failed: {e}")
        traceback.print_exc(file=sys.stderr)
        return []


class SSOHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/_openhost/auth_check"):
            is_owner = self.headers.get("X-OpenHost-Is-Owner", "").lower() == "true"
            cookies = self.headers.get("Cookie", "")
            has_session = "session-token" in cookies

            if is_owner and not has_session:
                self.send_response(401)
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        elif self.path.startswith("/_openhost/login"):
            session_cookies = _nextauth_login()

            if not session_cookies:
                self.send_response(302)
                self.send_header("Location", f"https://{APP_HOST}/auth/login")
                self.end_headers()
                log("SSO login failed, redirecting to native login")
                return

            self.send_response(302)
            for cookie in session_cookies:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Location", "/")
            self.end_headers()
            log("SSO login successful")

        else:
            self.send_response(404)
            self.end_headers()


def main():
    server = http.server.HTTPServer((LISTEN_HOST, LISTEN_PORT), SSOHandler)
    log(f"SSO sidecar listening on {LISTEN_HOST}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
