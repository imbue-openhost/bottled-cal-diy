# Cal.diy (Cal.com for OpenHost)

Self-hosted Cal.com scheduling packaged for OpenHost with automatic SSO.

## Architecture

Single container running:
- PostgreSQL 15 (data + NextAuth sessions via Prisma)
- Redis (caching)
- Cal.com Next.js app (port 3000, from calcom/cal.com Docker image)
- Auth proxy (port 8080, Pattern B2 - direct DB session injection)

## SSO Pattern: B2

Cal.com uses NextAuth with database sessions. The auth proxy creates sessions
directly in the PostgreSQL `Session` table -- no passwords are stored on disk.

Flow:
1. Owner visits a dashboard path (e.g. /event-types, /settings)
2. Auth proxy detects owner (X-OpenHost-Is-Owner header) without session cookie
3. Generates UUID session token, INSERTs into Session table
4. Sets `__Secure-next-auth.session-token` cookie, 302 redirects
5. Cal.com reads the session from the database and treats the owner as logged in

## Public Pages

Booking pages (e.g. /admin/30min) are public by default. The auth proxy only
triggers auto-login on dashboard prefixes (/settings, /event-types,
/availability, /apps, /workflows, /getting-started, /bookings, /teams).

The openhost.toml sets `public_paths = ["/"]` so the OpenHost router allows
anonymous access to all paths. The auth proxy selectively auto-logins the
owner only on dashboard paths.

## First Boot

The bootstrap script creates an admin user with:
- Email: admin@{ZONE_DOMAIN}
- Username: admin
- Role: ADMIN
- completedOnboarding: true (skips setup wizard)
- Random bcrypt password (never stored on disk)

## Resources

- Memory: 2048 MB
- CPU: 1000 millicores
- Persistent data: PostgreSQL data, secrets file, bootstrap marker
