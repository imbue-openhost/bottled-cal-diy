#!/usr/bin/env python3
"""
bootstrap_admin.py - First-boot admin user creation for Cal.diy

Creates the admin user directly in the Cal.com PostgreSQL database via psql.
Pattern B2: no password is stored on disk. The password is random and only
exists in the bcrypt hash in the database. Auth proxy injects sessions directly.

Cal.com Prisma schema (relevant tables):
  - "users" table: id (int), email, username, name, password (bcrypt), role,
    completedOnboarding, timeZone, etc.
  - "Session" table: id (text/cuid), sessionToken (text/uuid), userId (int), expires (timestamp)
"""

import hashlib
import os
import secrets
import subprocess
import sys
import time

DB_HOST = "127.0.0.1"
DB_PORT = "5432"
DB_NAME = "calendso"
DB_USER = "calcom"

ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "localhost")
ADMIN_EMAIL = f"admin@{ZONE_DOMAIN}"
ADMIN_USERNAME = "admin"
ADMIN_NAME = "Admin"
ADMIN_TIMEZONE = "America/Chicago"

# Marker file so we know bootstrap ran (NOT a credential -- just a flag)
APP_DATA = os.environ.get("OPENHOST_APP_DATA_DIR", "/data/app_data/cal-diy")
BOOTSTRAP_MARKER = os.path.join(APP_DATA, ".bootstrap_done")


def log(msg: str) -> None:
    print(f"[openhost:bootstrap] {msg}", flush=True)


def run_sql(sql: str) -> str:
    """Execute SQL via psql and return stdout."""
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
        timeout=30,
    )
    if result.returncode != 0:
        log(f"SQL error: {result.stderr.strip()}")
    return result.stdout.strip()


def wait_for_db(max_wait: int = 120) -> None:
    """Wait until PostgreSQL is responsive and the users table exists."""
    log("Waiting for database...")
    start = time.time()
    while time.time() - start < max_wait:
        try:
            result = run_sql("SELECT 1")
            if result == "1":
                # Check if the users table exists (Prisma migrations done)
                table_check = run_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_name = 'users')"
                )
                if table_check == "t":
                    log("Database is ready and users table exists.")
                    return
                else:
                    log("Database ready but users table not yet created. Waiting for Prisma migrations...")
        except Exception as e:
            log(f"DB not ready: {e}")
        time.sleep(3)
    # One more check with longer timeout
    log("WARNING: Timed out waiting for users table. Proceeding anyway...")


def bcrypt_hash(password: str) -> str:
    """
    Generate a bcrypt hash. We use Python's hashlib-based approach.
    Since the cal.com image may not have the bcrypt Python module,
    we shell out to node to use bcryptjs which cal.com already has installed.
    """
    result = subprocess.run(
        [
            "node", "-e",
            f"""
            const bcrypt = require('bcryptjs');
            const hash = bcrypt.hashSync({repr(password)}, 10);
            process.stdout.write(hash);
            """
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        # Fallback: try python hashlib (not bcrypt, but worth trying)
        log(f"Node bcrypt failed: {result.stderr.strip()}")
        log("Trying Python fallback...")
        # Try importing bcrypt
        try:
            import bcrypt as bc
            return bc.hashpw(password.encode(), bc.gensalt(10)).decode()
        except ImportError:
            # Last resort: use a sha256 hash (won't work for login, but
            # that's fine since Pattern B2 bypasses password auth)
            log("WARNING: No bcrypt available. Using sha256 placeholder hash.")
            log("This is acceptable because Pattern B2 never uses password login.")
            h = hashlib.sha256(password.encode()).hexdigest()
            return f"$sha256${h}"
    return result.stdout.strip()


def create_admin() -> None:
    """Create the admin user in the database if not already present."""

    # Check if any user already exists
    existing = run_sql(
        f"SELECT id FROM users WHERE email = '{ADMIN_EMAIL}' OR username = '{ADMIN_USERNAME}' LIMIT 1"
    )
    if existing:
        log(f"Admin user already exists (id={existing}). Skipping creation.")
        # Write marker
        with open(BOOTSTRAP_MARKER, "w") as f:
            f.write(existing)
        return

    # Generate a random password -- never stored on disk (Pattern B2)
    random_password = secrets.token_urlsafe(32)
    password_hash = bcrypt_hash(random_password)

    # Generate a user id (positive int, within safe range)
    user_id = secrets.randbelow(2_000_000_000) + 1

    log(f"Creating admin user: email={ADMIN_EMAIL}, username={ADMIN_USERNAME}, id={user_id}")

    # Insert the user
    # Cal.com's users table has many columns; we set the essential ones.
    # Prisma uses quoted column names matching the schema field names.
    sql = f"""
    INSERT INTO users (
        id,
        email,
        username,
        name,
        password,
        role,
        "completedOnboarding",
        "timeZone",
        "emailVerified",
        "identityProvider",
        "createdDate",
        metadata
    ) VALUES (
        {user_id},
        '{ADMIN_EMAIL}',
        '{ADMIN_USERNAME}',
        '{ADMIN_NAME}',
        '{password_hash}',
        'ADMIN',
        true,
        '{ADMIN_TIMEZONE}',
        NOW(),
        'CAL',
        NOW(),
        '{{}}'::jsonb
    )
    ON CONFLICT (email) DO NOTHING;
    """

    result = run_sql(sql)
    log(f"INSERT result: {result}")

    # Verify the user was created
    verify = run_sql(f"SELECT id FROM users WHERE email = '{ADMIN_EMAIL}'")
    if verify:
        log(f"Admin user created successfully (id={verify}).")
        # Write marker with user id (NOT a secret)
        with open(BOOTSTRAP_MARKER, "w") as f:
            f.write(verify)
    else:
        log("WARNING: Admin user creation may have failed. Check logs.")

    # Update the sequence if needed so future inserts don't collide
    run_sql(f"SELECT setval(pg_get_serial_sequence('users', 'id'), GREATEST({user_id}, (SELECT COALESCE(MAX(id), 1) FROM users)))")


def main() -> None:
    log("Starting bootstrap...")
    wait_for_db()
    create_admin()
    log("Bootstrap complete.")


if __name__ == "__main__":
    main()
