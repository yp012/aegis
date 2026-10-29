# Aegis

[![DevSecOps](https://github.com/yp012/aegis/actions/workflows/devsecops.yml/badge.svg?branch=main)](https://github.com/yp012/aegis/actions/workflows/devsecops.yml)

**Zero-Trust Access Control & Clearance Management Portal.** A security-focused full-stack
project for managing who may enter which physical zone, based on role, clearance tier, and
explicit time-bound grants, with a tamper-resistant audit trail. The finished system will
put a FastAPI API and a React UI behind a hardened Nginx edge, with PostgreSQL and Redis on
an internal network.

> **Status: work in progress. The foundation and authentication are complete; the policy
> engine, the audit hash chain, the domain endpoints and the UI are still being built.**
> Today the repo contains the database schema and its integrity guarantees, the
> configuration layer, a complete authentication API (Argon2id passwords, JWT access tokens,
> rotating refresh tokens with reuse detection, TOTP MFA, account lockout, Redis-backed rate
> limiting), the container/edge setup, and a DevSecOps CI pipeline that passes on GitHub
> ([run 40835243200](https://github.com/yp012/aegis/actions/runs/40835243200), all 5 job
> runs green). It has no zone, visitor, badge or audit endpoints yet, and the UI is a status
> page. Everything unbuilt is listed under [Roadmap](#roadmap-not-yet-implemented). Every
> number in this file was measured by a command shown in
> [How these were measured](#how-these-were-measured).

---

## What's implemented today

| Area | What exists (and was verified) |
| --- | --- |
| **API app** | FastAPI app factory (`app/main.py`) with CORS, `GET /api/health` and the `/api/v1/auth/*` routes below. OpenAPI/docs are disabled when `ENVIRONMENT=production`. Any `RedisError` becomes a generic `503`, because the API can't make a safe auth decision without its revocation and replay state. |
| **Fail-fast config** | `pydantic-settings` (`app/core/config.py`). The app refuses to start if `JWT_SECRET`, `BADGE_HMAC_SECRET` or `MFA_ENCRYPTION_KEY` is missing, shorter than 32 chars, or still set to the `.env.example` `CHANGE_ME` placeholder. It also refuses to start if `MFA_ENCRYPTION_KEY` isn't a valid Fernet key, if `COOKIE_SECURE=false` while `ENVIRONMENT=production`, if a CORS origin contains a wildcard, path or query, or if `TRUSTED_PROXIES` isn't a list of IPs/CIDRs. Secrets are `SecretStr`, and validation errors never echo the rejected value (`hide_input_in_errors`). |
| **Auth endpoints** | `POST /api/v1/auth/register`, `/login`, `/mfa/login`, `/mfa/setup`, `/mfa/verify-setup`, `/refresh`, `/logout`, and `GET /api/v1/auth/me` (`app/api/v1/auth.py`). Failures return one generic message per endpoint (`Invalid credentials`, `Invalid or expired session`), so a response doesn't reveal whether an account exists, is locked or is disabled. Request bodies reject unknown fields. |
| **Passwords** | Argon2id via argon2-cffi (RFC 9106 low-memory profile: t=3, m=64 MiB, p=4), 12–128 characters, transparently rehashed on login when parameters change. An unknown email still costs one Argon2 verification against a dummy hash, so every login path does the same work. |
| **Account lockout** | 5 consecutive failures lock the account for 15 minutes (`failed_login_count`, `locked_until`). Wrong TOTP codes count toward the same limit. The user row is read `SELECT … FOR UPDATE`, so concurrent attempts can't race the counter past 5. For MFA users the counter only resets after the second factor succeeds. |
| **JWT access tokens** | HMAC-signed (HS256 by default; only HS256/384/512 are accepted by config), 10-minute lifetime. Decoding pins the algorithm (so `alg: none` and algorithm confusion are rejected) and requires `exp`, `iat`, `nbf`, `iss`, `aud`, `sub`, `jti` and `type`. The `type` claim (`access`, `refresh`, `mfa_pending`) is compared with `hmac.compare_digest`, so one kind of token can never stand in for another. Authorization reads role, clearance and `is_active` from the **current DB row**, not the token, so a demotion or deactivation applies on the next request. |
| **Refresh-token rotation with reuse detection** | 7-day refresh tokens live only in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`. Each token is tracked in Redis and consumed atomically by a Lua script on use; a new one is issued every time. Presenting an already-used token means two parties hold it, so the user's **whole token family** is revoked: every active refresh token, plus every access token issued up to that second (a `revoked-before` timestamp). A refresh for a deactivated user also revokes everything. |
| **Access-token blacklist** | `POST /logout` puts the access token's `jti` on a Redis blacklist with a TTL equal to its remaining lifetime and deletes the caller's refresh token. Every authenticated request checks the blacklist and the `revoked-before` timestamp. |
| **TOTP MFA** | Enrollment returns an `otpauth://` URI and a QR code PNG; MFA is enabled only after a valid code confirms it. Secrets are stored Fernet-encrypted (`mfa_secret_encrypted`, key `MFA_ENCRYPTION_KEY`). Login for an MFA user returns a 5-minute, single-use `mfa_pending` token instead of a session. Codes are accepted for ±1 30-second step, and each accepted `(user, code)` pair is recorded in Redis with `SET NX` for 90 seconds, so a sniffed code can't be replayed, even by a concurrent request. |
| **Redis rate limiting** | Sliding-window log in one atomic Lua script, timed with Redis `TIME` so API replicas with skewed clocks agree (`app/core/rate_limit.py`). Global limit: 120 requests / 60 s per client IP, **fails open** if Redis is down. Auth limit: 5 requests / 60 s per client IP + email, per endpoint, **fails closed** (`503`) if Redis is down, so knocking Redis over doesn't unlock unlimited password guesses. A rejected request gets `429` JSON with a `Retry-After` header. |
| **Trusted-proxy handling** | `X-Forwarded-For` is honoured only when the TCP peer is in `TRUSTED_PROXIES`, and is then read right to left, skipping trusted hops, so a client can't spoof its IP by prepending addresses. Compose pins the edge nginx to a fixed address (`NGINX_EDGE_IP` on `EDGE_SUBNET`) and passes only that as `TRUSTED_PROXIES`. nginx overwrites (never appends to) `X-Forwarded-For`, and uvicorn runs with `--no-proxy-headers` so it doesn't rewrite the client address itself. |
| **API security headers** | A pure-ASGI middleware adds `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP, CORP, `Permissions-Policy`, `Cache-Control: no-store` and a deny-all CSP (`default-src 'none'`) to every response, including errors and CORS preflights. HSTS is added in production. Behind the edge, nginx hides the API's copies of the headers it sets itself, so each appears once. |
| **Data model** | 7 SQLAlchemy 2.x models with UUID primary keys (`gen_random_uuid()`), timezone-aware timestamps, and native PostgreSQL enum types for role, clearance, visitor type/status, access result, and subject type. |
| **DB integrity** | 11 `CHECK` constraints, e.g. a zone access grant must reference **exactly one** of user/visitor, occupancy must stay ≤ capacity, audit hashes must be 64-char lowercase hex, and `users.email = lower(email)`. Foreign-key delete behaviour is chosen per relation (see below). |
| **Case-insensitive email uniqueness** | The auth service trims and lowercases every email before insert and lookup, and the `email_lowercase` CHECK makes that a database guarantee, so the unique index on `email` can't hold both `Alice@x.io` and `alice@x.io`. |
| **Migrations** | Three Alembic migrations. The initial schema was autogenerated and reviewed by hand; enum types are created and dropped explicitly, so `downgrade base` → `upgrade head` round-trips cleanly (covered by a test). The second creates the restricted app role (below); the third adds the lowercase-email CHECK. A one-shot `migrate` compose service runs `alembic upgrade head` as the schema owner and must exit 0 before the API starts. |
| **Append-only audit table** | The `audit_log_immutable` PostgreSQL trigger rejects every `UPDATE`, `DELETE` and `TRUNCATE` on `audit_logs`, including statements that match zero rows. [Proof below](#proof-the-audit-trigger-blocks-mutation). |
| **Least-privileged app DB role** | The API connects as `aegis_app` (`APP_DATABASE_URL`). Only migrations use the owner (`DATABASE_URL`). `aegis_app` is a `LOGIN` role with `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`. It owns no objects and is a member of no role. It has `SELECT, INSERT, UPDATE, DELETE` on the domain tables, **only `SELECT, INSERT` on `audit_logs`**, `USAGE` on sequences, and no access to `alembic_version`. Because it isn't the owner or a superuser, it can't `DISABLE TRIGGER`, `DROP` the table or trigger, or set `session_replication_role`. The migration reads the password from `APP_DB_PASSWORD` and sends it to PostgreSQL only as a SCRAM-SHA-256 verifier computed client-side (`app/db/scram.py`), so the plaintext never appears in SQL or server logs. The backend container's environment contains no `DATABASE_URL`, `POSTGRES_PASSWORD` or `APP_DB_PASSWORD`; compose passes it an explicit allowlist instead of `env_file`. [Proof below](#proof-the-app-role-cannot-bypass-the-trigger). |
| **Clearance ordering** | `Clearance` is an `IntEnum` (`Reliability`=1 < `Secret_Level_II`=2 < `Top_Secret`=3). `held.satisfies(required)` raises `TypeError` on anything that isn't a `Clearance`, so a stray `int` or string can't be compared silently. The PG enum is declared in the same order, so DB-side comparisons agree. Over the API, clearance travels as its label (`"Top_Secret"`), never a bare int. |
| **Authorization building blocks** | `require_roles(*roles)` and `require_clearance(min_level)` FastAPI dependencies (`app/core/deps.py`), tested, and checked against the current DB row. No domain endpoint uses them yet because none exist. |
| **Containers** | Multi-stage Dockerfiles for backend and frontend. **Every process in the stack runs as non-root** (measured uids: backend 10001, frontend/edge nginx 101, postgres 70, redis 999). |
| **Compose hardening** | `no-new-privileges` on all services. `cap_drop: [ALL]` and a read-only root filesystem on backend, frontend and edge nginx. Postgres and Redis sit on an `internal: true` network with no host ports, and Redis requires a password. Compose refuses to start if a required secret variable is empty. |
| **Edge (Nginx)** | Single entry point on `:8080` with a CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` and COOP headers. `limit_req` rate limiting at the edge: 20 r/s, burst 40 on `/api/`; 5 r/min, burst 5 on `/api/v1/auth/login`. `client_max_body_size 1m`. |
| **Frontend** | Vite + React + TypeScript + Tailwind build, served by unprivileged Nginx. Currently a single page that shows live API health; there is no login UI yet. |
| **CI pipeline** | `.github/workflows/devsecops.yml` defines 4 jobs: `secret-scan` (gitleaks); `backend` (ruff, ruff format, mypy, bandit, pip-audit, pytest + coverage); `frontend` (oxlint, build, npm audit); `containers` (image build for backend and frontend, non-root check, Trivy image and config scan, `fail-fast: false`). The backend job runs the 57 PostgreSQL integration tests against a `postgres:16` service container; in CI they fail rather than skip if the database is missing. Redis-dependent tests use fakeredis with a real Lua runtime (`lupa`), so the rate-limit and rotation scripts actually execute. Test secrets are generated randomly per run, and third-party actions are pinned to commit SHAs. [Run 40835243200](https://github.com/yp012/aegis/actions/runs/40835243200) on commit `c95789a` passed all 5 job runs; its backend job reported `253 passed` at 97.40% coverage. |

### Foreign-key choices

| Relation | On delete | Why |
| --- | --- | --- |
| `audit_logs.actor_id → users` | `RESTRICT` | An actor with audit history can't be hard-deleted; deactivate instead. `SET NULL` would be an `UPDATE`, which the trigger blocks anyway. |
| `zone_access_grants.granted_by → users` | `RESTRICT` | Keeps accountability for who granted access. |
| `visitors.host_user_id → users` | `RESTRICT` | A visitor always has a responsible host. |
| `zone_access_grants.{user_id, visitor_id, zone_id}` | `CASCADE` | A grant is meaningless without its subject or zone. |
| `badges.visitor_id → visitors` | `CASCADE` | A badge belongs to exactly one visitor. |
| `access_events.zone_id → zones` | `SET NULL` | Access history survives removal of a zone. |

---

## Proof: the audit trigger blocks mutation

Run against the stack's PostgreSQL 16.15 container (migrated by the backend on startup), after
inserting one valid row:

```text
$ docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -e 2>&1' <<'EOF'
UPDATE audit_logs SET action = 'tampered' WHERE id = 1;
DELETE FROM audit_logs WHERE id = 1;
TRUNCATE audit_logs;
SELECT id, action, left(entry_hash, 12) AS entry_hash FROM audit_logs;
EOF
UPDATE audit_logs SET action = 'tampered' WHERE id = 1;
ERROR:  audit_logs is append-only: UPDATE is not permitted
HINT:  Audit entries can only be inserted.
CONTEXT:  PL/pgSQL function audit_logs_reject_mutation() line 3 at RAISE
DELETE FROM audit_logs WHERE id = 1;
ERROR:  audit_logs is append-only: DELETE is not permitted
HINT:  Audit entries can only be inserted.
CONTEXT:  PL/pgSQL function audit_logs_reject_mutation() line 3 at RAISE
TRUNCATE audit_logs;
ERROR:  audit_logs is append-only: TRUNCATE is not permitted
HINT:  Audit entries can only be inserted.
CONTEXT:  PL/pgSQL function audit_logs_reject_mutation() line 3 at RAISE
SELECT id, action, left(entry_hash, 12) AS entry_hash FROM audit_logs;
 id |   action    |  entry_hash
----+-------------+--------------
  1 | system.init | aeebad4a796f
(1 row)
```

It is a single `BEFORE UPDATE OR DELETE OR TRUNCATE ... FOR EACH STATEMENT` trigger that raises
SQLSTATE `23001`. The same behaviour is asserted in `backend/tests/test_migrations.py`.

## Proof: the app role cannot bypass the trigger

The trigger alone doesn't stop the table owner or a superuser. The API therefore connects as
`aegis_app`, which is neither. This was run on 2026-10-29 against a freshly started stack
(PostgreSQL 16.15). It connects over the network with `aegis_app`'s password, i.e. the
credential an attacker would steal from the API container (run with `APP_DB_PASSWORD` from
`.env` exported in your shell):

```text
$ docker compose exec -T -e PGPASSWORD="$APP_DB_PASSWORD" postgres \
    sh -c 'psql -h postgres -U aegis_app -d "$POSTGRES_DB" -e 2>&1' <<'EOF'
SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser;
INSERT INTO audit_logs (prev_hash, entry_hash, action, resource)
  VALUES (repeat('0', 64), repeat('a', 64), 'system.init', 'audit_logs');
UPDATE audit_logs SET action = 'tampered' WHERE id = 1;
DELETE FROM audit_logs WHERE id = 1;
TRUNCATE audit_logs;
ALTER TABLE audit_logs DISABLE TRIGGER audit_log_immutable;
SET session_replication_role = replica;
DROP TABLE audit_logs;
SELECT id, action FROM audit_logs;
EOF
SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser;
 current_user | superuser
--------------+-----------
 aegis_app    | f
(1 row)

INSERT INTO audit_logs (prev_hash, entry_hash, action, resource)
  VALUES (repeat('0', 64), repeat('a', 64), 'system.init', 'audit_logs');
INSERT 0 1
UPDATE audit_logs SET action = 'tampered' WHERE id = 1;
ERROR:  permission denied for table audit_logs
DELETE FROM audit_logs WHERE id = 1;
ERROR:  permission denied for table audit_logs
TRUNCATE audit_logs;
ERROR:  permission denied for table audit_logs
ALTER TABLE audit_logs DISABLE TRIGGER audit_log_immutable;
ERROR:  must be owner of table audit_logs
SET session_replication_role = replica;
ERROR:  permission denied to set parameter "session_replication_role"
DROP TABLE audit_logs;
ERROR:  must be owner of table audit_logs
SELECT id, action FROM audit_logs;
 id |   action
----+-------------
  1 | system.init
(1 row)
```

In the same stack, the API's own connection reported `current_user = aegis_app,
rolsuper = false`. A wrong password was rejected with `password authentication failed for
user "aegis_app"`, and `pg_authid.rolpassword` starts with `SCRAM-SHA-256$4096:`.
`backend/tests/test_app_role.py` (24 integration tests) asserts the successful INSERT/SELECT
and each refusal above, the refusals with SQLSTATE `42501`. It also covers `DISABLE TRIGGER ALL`, `DROP TRIGGER`, `DROP TABLE zones`,
`CREATE TABLE`, reading `alembic_version` and `SET ROLE <owner>`. It also checks that the role
owns nothing, belongs to no role, and still has full DML on ordinary tables.

## Proof: refresh-token reuse revokes the session family

Run on 2026-10-29 through the edge (`http://localhost:8080`) against a freshly started stack
at commit `c95789a`. `jar.old` is a copy of the cookie jar taken before the first refresh,
i.e. a stolen refresh token:

```text
POST /api/v1/auth/register  (first user, becomes Admin)       → 201
POST /api/v1/auth/login                                      → 200 {"access_token": …}
GET  /api/v1/auth/me        (Bearer access token)            → 200 {"email":"admin@example.com","role":"Admin",…}
POST /api/v1/auth/refresh   (current cookie)                 → 200, cookie rotated
POST /api/v1/auth/refresh   (jar.old: the already-used token) → 401 {"detail":"Invalid or expired session"}
GET  /api/v1/auth/me        (the original access token)      → 401   ← family revoked
```

A second session then logged out (`204`), and its access token was rejected on the next
`/me` (`401`). Redis held only namespaced keys afterwards (`aegis:rt:*`,
`aegis:revoked-before:*`, `aegis:ratelimit:*`). The rate-limit keys carried the host's
address (`172.29.53.1`), not the edge nginx's (`172.29.53.10`), confirming the client IP was
taken from `X-Forwarded-For` only because the peer was the trusted edge.
`backend/tests/test_auth_api.py`, `test_auth_service.py`, `test_security.py`,
`test_deps.py` and `test_rate_limit.py` cover the same paths plus forged, expired,
wrong-type and `alg: none` tokens, TOTP replay, lockout, and Redis outages.

---

## Architecture (as built)

```text
                         docker network "edge" (EDGE_SUBNET, nginx pinned to NGINX_EDGE_IP)
 Browser ──:8080──▶ ┌──────────────────────────────┐
                    │ nginx (edge)        uid 101  │  CSP + security headers, limit_req,
                    │ read-only fs, cap_drop ALL   │  1 MB body cap, overwrites X-Forwarded-For
                    └───────┬──────────────┬───────┘
                       /    │              │ /api/
                            ▼              ▼
   ┌──────────────────────────────┐  ┌──────────────────────────────────┐
   │ frontend: nginx + React build│  │ backend: FastAPI / uvicorn       │
   │ uid 101  [SCAFFOLD: health   │  │ uid 10001, read-only fs          │
   │ status page only]            │  │ /api/health, /api/v1/auth/*      │
   └──────────────────────────────┘  │ trusts XFF only from the edge IP │
                                     └───────┬──────────────┬───────────┘
                   docker network "backend"  │              │
                   (internal: true, no host  ▼              ▼
                    ports published)  ┌───────────────┐ ┌──────────────────────┐
                                      │ PostgreSQL 16 │ │ Redis 7    uid 999   │
                                      │ uid 70        │ │ refresh-token state, │
                                      │ schema +      │ │ access blacklist,    │
                                      │ audit trigger │ │ TOTP replay cache,   │
                                      │ (as aegis_app)│ │ rate-limit windows   │
                                      └───────────────┘ └──────────────────────┘
```

The backend connects to PostgreSQL as the restricted `aegis_app` role. A one-shot `migrate`
container (same image, network `backend` only) runs `alembic upgrade head` as the schema
owner, then exits. The `backend` service waits for it with `service_completed_successfully`.

### Redis keys (all prefixed `aegis:`)

| Key | Purpose | Lifetime |
| --- | --- | --- |
| `rt:<jti>` | Refresh token state `{user_id, state=active\|used}` | until the token expires |
| `rt-user:<user_id>` | Set of the user's active refresh-token jtis | refresh lifetime |
| `revoked-before:<user_id>` | Access tokens issued at or before this second are dead | access lifetime + 60 s |
| `blacklist:<jti>` | Logged-out access token | its remaining lifetime |
| `mfa-pending-used:<jti>` | `mfa_pending` token already exchanged | its remaining lifetime |
| `totp-used:<user_id>:<code>` | Accepted TOTP code (replay guard) | 90 s |
| `ratelimit:global:<ip>` / `ratelimit:auth:<path>:<ip>\|<email>` | Sliding-window logs | the window |

### Data model (7 tables)

```text
users ─┬─< visitors            (host_user_id, RESTRICT)
       ├─< zone_access_grants  (user_id CASCADE; granted_by RESTRICT)
       └─< audit_logs          (actor_id RESTRICT, nullable for system events)

visitors ─┬─< zone_access_grants (visitor_id CASCADE)
          └─< badges             (visitor_id CASCADE; jti UNIQUE)

zones ─┬─< zone_access_grants  (zone_id CASCADE)
       └─< access_events       (zone_id SET NULL)

access_events.subject_id → users.id OR visitors.id (polymorphic, no FK; subject_type enum)
zone_access_grants: CHECK exactly one of (user_id, visitor_id) is set
```

| Table | Key columns |
| --- | --- |
| `users` | `email` (unique, CHECK lowercase), `role`, `clearance`, `is_active`, `mfa_enabled`, `mfa_secret_encrypted`, `failed_login_count`, `locked_until` |
| `zones` | `name` (unique), `min_clearance`, `capacity`, `current_occupancy` |
| `zone_access_grants` | `user_id` / `visitor_id`, `zone_id`, `granted_by`, `expires_at`, `revoked_at` |
| `visitors` | `visitor_type`, `host_user_id`, `clearance`, `status`, `visit_start`, `visit_end` |
| `badges` | `visitor_id`, `jti` (unique), `issued_at`, `expires_at`, `revoked`, `last_scanned_at` |
| `access_events` | `subject_type`, `subject_id`, `zone_id`, `result`, `reason`, `ip` (INET) |
| `audit_logs` | `id` (bigserial), `prev_hash`, `entry_hash` (unique), `actor_id`, `action`, `resource`, `payload` (JSONB) |

---

## Tech stack

Versions are the exact pins in `backend/requirements.txt` (40 pinned packages, direct and
transitive) and the versions resolved in `frontend/package-lock.json`.

| Layer | Technology |
| --- | --- |
| Language | Python 3.12 (`python:3.12-slim-bookworm`), TypeScript 7.0.2, Node 24 (build stage) |
| API | FastAPI 0.162.0, uvicorn 0.54.0, Pydantic 2.14.1, pydantic-settings 2.16.1 |
| Data | SQLAlchemy 2.1.6, Alembic 1.20.1, psycopg 3.3.6, PostgreSQL 16 (`postgres:16-alpine`, ran 16.15) |
| Auth & crypto | PyJWT 2.15.1, argon2-cffi 25.1.0 (Argon2id), PyOTP 2.10.0, qrcode 8.2, cryptography 50.0.2 (Fernet) |
| Cache / ephemeral state | Redis 7 (`redis:7-alpine`) via redis-py 8.1.0: token state, blacklist, TOTP replay cache, rate limiting |
| Frontend | React 19.3.1, Vite 8.3.5, Tailwind CSS 4.3.3, oxlint 1.90.0 |
| Edge | `nginxinc/nginx-unprivileged:1.30.6-alpine3.24` (edge proxy and static frontend) |
| Quality / security | ruff 0.17.3, mypy 2.4.0, bandit 1.9.4, pip-audit 2.10.1, pytest 9.2.0, pytest-cov 7.1.0, fakeredis 2.40.0 + lupa 2.8 (Lua for tests); gitleaks and Trivy in CI |

---

## Quick start

Prerequisites: Docker with Compose v2, and `python3` (standard library only, used to
generate secrets).

```bash
git clone <this-repo> aegis && cd aegis

# 1. Create .env with freshly generated secrets (the app refuses to start on CHANGE_ME values).
cp .env.example .env
gen() { python3 -c "import secrets; print(secrets.token_urlsafe(48))"; }
fernet() { python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"; }
sed -i.bak \
  -e "s|CHANGE_ME_postgres_password|$(gen)|g" \
  -e "s|CHANGE_ME_app_db_password|$(gen)|g" \
  -e "s|CHANGE_ME_redis_password|$(gen)|g" \
  -e "s|^JWT_SECRET=.*|JWT_SECRET=$(gen)|" \
  -e "s|^BADGE_HMAC_SECRET=.*|BADGE_HMAC_SECRET=$(gen)|" \
  -e "s|^MFA_ENCRYPTION_KEY=.*|MFA_ENCRYPTION_KEY=$(fernet)|" \
  .env && rm .env.bak

# 2. Build and start (the migrate service applies migrations and creates aegis_app first).
docker compose up -d --build        # or: make up

# 3. Check it.
curl http://localhost:8080/api/health   # {"status":"ok"}

# 4. Create the bootstrap Admin (only works while the users table is empty; do this at once).
curl -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","full_name":"Admin","password":"choose-a-long-passphrase"}' \
  http://localhost:8080/api/v1/auth/register
curl -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"choose-a-long-passphrase"}' \
  http://localhost:8080/api/v1/auth/login   # {"access_token":"…","token_type":"bearer","expires_in":600}
```

The edge network defaults to `172.29.53.0/24` with nginx at `172.29.53.10`. If that subnet
clashes with something on your machine, change `EDGE_SUBNET` and `NGINX_EDGE_IP` together
in `.env`.

| URL | What you get |
| --- | --- |
| http://localhost:8080/ | React status page showing live API health |
| http://localhost:8080/api/health | `{"status":"ok"}` |
| http://localhost:8080/api/v1/auth/* | Auth endpoints (see [What's implemented today](#whats-implemented-today)) |
| http://localhost:8080/api/openapi.json | OpenAPI schema (non-production only) |

Stop with `docker compose down` (`make down`). Add `-v` to also delete the database volume.

The `fernet()` helper produces the same format as `cryptography.fernet.Fernet.generate_key()`
(32 random bytes, url-safe base64).

### Lint and test

```bash
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.txt
(cd frontend && npm ci)

make lint   # ruff check, ruff format --check, mypy, bandit, oxlint
make test   # pytest with coverage (80% gate), then the frontend production build
```

Locally without a database, the 57 integration tests are **skipped** (196 passed,
57 skipped, 85.50% coverage, because the HTTP-level auth tests need PostgreSQL). In CI
(`CI=true`) they never skip: without a database they error out (verified locally:
`196 passed, 57 errors`). Redis is never needed for tests; they use fakeredis.

### Integration tests (real PostgreSQL)

These cover the trigger, the constraints, enum ordering, the migration round-trip, the
restricted `aegis_app` role (it logs in with `APP_DB_PASSWORD`, which `tests/conftest.py`
defaults to a test value) and the auth API end to end. They **downgrade the target database
to base** and drop the `aegis_app` role, so only point them at a disposable database
**server**:

```bash
docker run -d --rm --name aegis-test-pg \
  -e POSTGRES_USER=aegis -e POSTGRES_PASSWORD=aegis -e POSTGRES_DB=aegis_test \
  -p 127.0.0.1:55432:5432 postgres:16-alpine
until docker exec aegis-test-pg pg_isready -h 127.0.0.1 -U aegis -q; do sleep 1; done
cd backend && AEGIS_TEST_DATABASE_URL=postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis_test \
  .venv/bin/pytest -m integration -v
docker stop aegis-test-pg
```

`make seed` and `make bench` are deliberately disabled: they print "not implemented yet" and
exit non-zero.

---

## Project structure

`●` = implemented · `○` = scaffold (docstring-only placeholder, no code yet). Of the 47 Python
files in `backend/app`, 25 contain code and 22 are placeholders (9 of those are package
`__init__.py` files).

```text
.
├── .github/workflows/devsecops.yml    ● 4-job DevSecOps pipeline (green on `c95789a`)
├── backend
│   ├── alembic/
│   │   ├── env.py                     ● settings-driven; accepts an injected connection
│   │   ├── versions/…_initial_schema.py  ● 7 tables, 6 enums, audit trigger
│   │   ├── versions/…_restricted_app_role.py  ● least-privileged aegis_app role + grants
│   │   └── versions/…_users_email_lowercase.py  ● CHECK email = lower(email)
│   ├── app
│   │   ├── main.py                    ● app factory, security headers, Redis-down → 503, /api/health
│   │   ├── api/v1/router.py           ● mounts the auth router
│   │   ├── api/v1/auth.py             ● register, login, MFA, refresh, logout, me
│   │   ├── api/v1/{users,zones,visitors,badges,audit,dashboard}.py         ○
│   │   ├── core/config.py             ● fail-fast settings (API vs. migration settings)
│   │   ├── core/security.py           ● Argon2id, JWT issue/verify with pinned algorithm
│   │   ├── core/deps.py               ● current user, require_roles, require_clearance
│   │   ├── core/rate_limit.py         ● Redis sliding-window limiter, trusted-proxy client IP
│   │   ├── core/redis.py              ● Redis client lifecycle, namespaced keys
│   │   ├── core/crypto.py             ○
│   │   ├── db/{base,session,types}.py ● declarative base, engine, get_db, column types
│   │   ├── db/scram.py                ● client-side SCRAM-SHA-256 verifier for role passwords
│   │   ├── models/                    ● 7 models + enums (Clearance helper)
│   │   ├── schemas/{auth,user}.py     ● request/response models (strict, extra="forbid")
│   │   ├── schemas/{zone,visitor,badge,audit,dashboard}.py                 ○
│   │   ├── services/auth_service.py   ● login, lockout, rotation, reuse detection, revocation
│   │   ├── services/mfa_service.py    ● TOTP enrollment/verification, Fernet, replay guard
│   │   └── services/{policy_engine,audit_chain,badge_service}.py           ○
│   ├── tests/                         ● 13 test modules (253 tests) + conftest.py, pg.py helpers
│   ├── Dockerfile                     ● multi-stage, uid 10001, uvicorn --no-proxy-headers
│   ├── pyproject.toml                 ● ruff / mypy / pytest / coverage / bandit config
│   └── requirements*.txt              ● fully pinned
├── frontend
│   ├── src/App.tsx                    ● API health status page (scaffold UI)
│   ├── Dockerfile, nginx.conf         ● multi-stage build → unprivileged nginx, uid 101
│   └── package.json, vite.config.ts   ●
├── nginx/nginx.conf                   ● edge proxy: headers, CSP, limit_req, XFF overwrite
├── scripts/{seed_demo_data,benchmark_metrics}.py   ○
├── docker-compose.yml                 ● 5 services + one-shot migrate job, hardened, pinned edge IP
├── Makefile                           ● up / down / lint / test (seed, bench → "not implemented")
└── .env.example                       ● placeholders only
```

---

## Threat model (STRIDE)

Scoped to what exists plus what's planned. **Implemented** means it is in the code and was
verified. **Planned** means it is not built.

| STRIDE | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| **S**poofing | Someone calls the API as another user | JWT access tokens (pinned algorithm, required claims, typed), Argon2id passwords, TOTP MFA, DB-row authorization | Implemented |
| Spoofing | Online password guessing / credential stuffing | Per-IP+email auth rate limit (fails closed), 5-failure / 15-minute lockout, edge `limit_req` on login, generic error messages, equal Argon2 work for unknown accounts | Implemented |
| Spoofing | Stolen refresh token reused | Rotation on every use; reuse of a spent token revokes the whole family (refresh and access) | Implemented |
| Spoofing | Sniffed TOTP code or `mfa_pending` token replayed | Accepted codes cached 90 s with `SET NX`; `mfa_pending` tokens are single-use and expire in 5 minutes | Implemented |
| Spoofing | Token of one kind used as another (e.g. refresh as access) | `type` claim checked on every decode (`hmac.compare_digest`) | Implemented |
| Spoofing | Client spoofs its IP to dodge rate limits | `X-Forwarded-For` trusted only from the pinned edge IP, read right to left; nginx overwrites it; uvicorn proxy headers off | Implemented |
| Spoofing | Anyone claims the first Admin account on a fresh deployment | Registration is open only while the users table is empty | **Partial**: see Known limitations |
| Spoofing | Deployment runs with default/weak secrets | Startup rejects missing, short (<32), or `CHANGE_ME` secrets and invalid Fernet keys; compose refuses empty secret vars | Implemented |
| Spoofing | Direct access to DB or Redis | Both on an `internal: true` network with no published ports; Redis `requirepass` | Implemented |
| **T**ampering | Audit history edited or erased | `audit_log_immutable` trigger blocks UPDATE, DELETE and TRUNCATE | Implemented |
| Tampering | Stolen API DB credential used to disable the trigger or rewrite the audit trail | API runs as `aegis_app`: not owner, not superuser, only `SELECT`/`INSERT` on `audit_logs`; the owner credential is only in the one-shot `migrate` container | Implemented |
| Tampering | Inconsistent or forged rows (grant for two subjects, occupancy > capacity, malformed hash, mixed-case duplicate email) | DB `CHECK` constraints, native enums, FK rules | Implemented |
| Tampering | Forged or altered JWT (`alg: none`, algorithm confusion, edited claims) | HMAC signature with algorithm pinned in config; PyJWT rejects any other `alg` | Implemented |
| Tampering | Audit rows inserted out of chain | SHA-256 hash chain writer and verifier | **Planned**: the table exists, but nothing writes or verifies the chain |
| **R**epudiation | User denies an action or an access attempt | `audit_logs` and `access_events` written by the app on every action | **Planned**: schema exists, no writers yet; logins, failures, lockouts and token-reuse events are not recorded |
| **I**nformation disclosure | Secrets leaked via logs or errors | `SecretStr`, `hide_input_in_errors` (tested) | Implemented |
| Information disclosure | Account enumeration | One generic message per auth endpoint; the same Argon2 work whether or not the account exists, is locked or is disabled | Implemented (bootstrap `register` returns 409 for a taken email, but only an Admin can call it once a user exists) |
| Information disclosure | Refresh token stolen by XSS or sent cross-site | `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`, never in a response body | Implemented |
| Information disclosure | Tokens or personal data kept by caches | `Cache-Control: no-store` on every API response | Implemented |
| Information disclosure | Clickjacking, MIME sniffing, XSS impact | CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` at the edge; deny-all CSP on API responses | Implemented |
| Information disclosure | API schema exposed in production | `/api/docs` and `/api/openapi.json` disabled when `ENVIRONMENT=production` | Implemented |
| Information disclosure | TOTP secrets readable from the DB | Fernet-encrypted `mfa_secret_encrypted` | Implemented |
| Information disclosure | Secrets committed to git | `.env` gitignored; gitleaks on every push/PR; per-run random CI secrets | Implemented. gitleaks' first run caught a committed dummy CI key, which is now removed and allowlisted by exact fingerprint only |
| **D**enial of service | Request floods | nginx `limit_req` (20 r/s burst 40 on `/api/`; 5 r/min burst 5 on login), 1 MB body cap | Implemented (edge) |
| Denial of service | Per-user/per-route abuse behind the proxy | Redis sliding-window limits: 120/min per IP globally, 5/min per IP+email per auth endpoint | Implemented |
| Denial of service | Huge passwords used to burn Argon2 CPU | Password length capped at 128 characters before hashing | Implemented |
| Denial of service | Attacker locks a victim out by failing logins on purpose | Per-IP+email rate limit slows it; lockout is still per account | **Accepted risk**: see Known limitations |
| **E**levation of privilege | Container breakout or privilege gain | Non-root in all 5 services, `no-new-privileges`; `cap_drop: ALL` and read-only rootfs on backend/frontend/edge | Implemented |
| Elevation of privilege | Self-registration as Admin | After bootstrap, only an authenticated Admin can register users or choose a role | Implemented |
| Elevation of privilege | A demoted or deactivated user keeps acting until the token expires | Role, clearance and `is_active` read from the DB on every request; deactivated users' refresh attempts revoke all their sessions | Implemented |
| Elevation of privilege | Personnel reaching Admin or SecurityOfficer functions, or entering zones above their clearance | Role checks, plus a policy engine requiring `is_active` ∧ `clearance.satisfies(zone.min_clearance)` ∧ an unexpired grant | **Partial**: `require_roles` / `require_clearance` dependencies exist and are tested; the zone policy engine and the endpoints that would use them are not built |

### Known limitations (honest list)

- **Bootstrap registration is open.** While the `users` table is empty, anyone who can reach
  `POST /api/v1/auth/register` becomes the Admin. A PostgreSQL advisory lock stops two
  concurrent requests from both winning, but there is no setup token or CLI-only bootstrap,
  so on a fresh deployment the operator has to register first, before exposing the port.
- **Login events are not in the audit log.** Successful and failed logins, lockouts, MFA
  enrollment, logouts and refresh-token reuse detection are enforced but not recorded
  anywhere persistent; the audit hash-chain writer doesn't exist yet. Token-reuse detection
  in particular revokes sessions silently.
- **The edge's 429 is an nginx HTML page.** When nginx's `limit_req` rejects a request it
  returns its default `text/html` "429 Too Many Requests" page with no `Retry-After`. The
  API's own limiter returns JSON with `Retry-After`. On `/api/v1/auth/login` both limits are
  5 per minute, so in practice the edge answers first: 10 rapid logins measured
  5 × `401 application/json` then 5 × `429 text/html`. A client has to handle both shapes.
- **Lockout can be used against a victim.** 5 wrong passwords from anywhere lock the
  account for 15 minutes. The per-IP+email rate limit slows this from a single IP but not
  from many. There is no CAPTCHA, unlock flow or notification.
- **No self-service account management yet.** There is no password change, MFA disable,
  MFA recovery codes, or Admin endpoint to reset MFA or unlock a user; recovery currently
  means editing the database.
- **Redis is a hard dependency for auth and is single-node.** If Redis is down, auth
  endpoints and authenticated requests return `503` (by design: fail closed); only the
  global rate limiter fails open. Redis runs with AOF persistence and no replication or
  Sentinel. Flushing Redis invalidates every refresh token (users log in again) and forgets
  the blacklist, so a logged-out access token would be accepted again for the rest of its
  lifetime (at most 10 minutes).
- **Access tokens are bearer tokens in the JSON body.** The future UI must keep them in
  memory, not `localStorage`. A stolen access token works until it expires or the user
  logs out (at most 10 minutes).
- **The owner/superuser can still bypass the trigger.** Migrations run as `POSTGRES_USER`,
  which the official image makes a superuser. Whoever holds `DATABASE_URL` (the `migrate`
  container, or anyone with `.env` or host access) can still `DISABLE TRIGGER` or `DROP`.
  The restricted role closes this for the **API credential** only. A separate,
  non-superuser owner role was not set up.
- **Changing `APP_DB_PASSWORD` doesn't rotate the role's password by itself.** The password
  is set when the role migration runs, and `alembic upgrade head` does nothing once the
  database is at head. To rotate, change both `APP_DB_PASSWORD` and `APP_DATABASE_URL`, then
  run `ALTER ROLE aegis_app PASSWORD …` as the owner (or downgrade to `cb65e740a2cf` and
  upgrade again).
- **Future tables get DML grants automatically.** `ALTER DEFAULT PRIVILEGES` gives `aegis_app`
  `SELECT/INSERT/UPDATE/DELETE` on tables that later migrations create as the owner. A new
  append-only table must `REVOKE` explicitly, as the role migration does for `audit_logs`.
- **gitleaks on push scans only the pushed commits.** In run 40835243200 it scanned
  1 commit. A full-history scan happens only on a manual `workflow_dispatch` run, and none
  has been run on GitHub yet. (A local full-history scan with the same gitleaks version,
  8.24.3, found no leaks on 2026-10-27; not re-run since.)
- **The compose edge proxy uses the upstream nginx image unmodified**, and CI only scans the
  images it builds. On 2026-10-27, Trivy 0.70.0 reported 3 fixable HIGH CVEs in it
  (`curl`/`libcurl`, `brotli-libs`) that upstream hadn't rebuilt for yet. The frontend image
  patches these with `apk upgrade`; the edge container does not. Not re-measured since.
- **CI ignores CVEs that have no fix yet** (`ignore-unfixed: true`). On 2026-10-27 the backend
  image carried 61 such HIGH/CRITICAL findings, all from the Debian 12 base image
  (53 `affected`, 7 `fix_deferred`, 1 `will_not_fix`; mostly `util-linux` libraries). They
  fail the gate automatically once Debian ships a fix. Moving to `python:3.12-slim-trixie`
  measured 44 instead of 61, which helps but isn't a fix; it's a candidate follow-up. Not
  re-measured since.
- **Coverage is measured over code that exists.** The 22 placeholder modules have no
  statements, so they neither add to nor subtract from the percentage. Without a database,
  coverage drops to 85.50% because the HTTP-level auth tests are integration tests.
- **Swagger UI won't render through the edge.** In non-production, `/api/docs` returns 200,
  but it loads its JS/CSS from `cdn.jsdelivr.net`, which the edge CSP (`script-src 'self'`)
  doesn't allow. Inferred from the CSP and the page source; not browser-tested.
  `/api/openapi.json` works.
- **API responses through the edge carry two `Content-Security-Policy` headers**: the API's
  deny-all policy and the edge's site policy. Browsers enforce both, so the stricter one
  wins and nothing is weakened, but it is redundant. (The other duplicated headers, including
  the ones on `/` noted in earlier versions of this README, are now hidden by
  `proxy_hide_header`; measured once each on 2026-10-29.)
- **No documented non-Docker dev server yet.** Only the Docker path and the test commands
  above are verified.

---

## Metrics (measured)

Measured **2026-10-29** on an Apple M2 with 8 GB RAM, macOS 26.6, Docker 29.5.3
(Docker Desktop), on the exact tree committed as
[`c95789a`](https://github.com/yp012/aegis/commit/c95789a0da0b541e06562d4c17f50618de4631e4)
(clean working tree apart from this README). The CI rows come from GitHub Actions
[run 40835243200](https://github.com/yp012/aegis/actions/runs/40835243200) on that same commit.

| Metric | Value |
| --- | --- |
| Tests, with PostgreSQL (`AEGIS_TEST_DATABASE_URL` set) | **253 passed**, 0 failed, 0 skipped (also 253 passed with `CI=true`) |
| Tests, without a database (`make test`) | **196 passed**, 57 skipped (the integration tests) |
| Tests, `CI=true` without a database | 196 passed, 57 errors (integration tests refuse to skip in CI, as designed) |
| Integration tests (`-m integration`) | **57 passed**: 25 auth API, 24 app role, 8 migrations |
| Tests per module | security 36 · deps 30 · config 28 · auth_service 26 · clearance 26 · auth_api 25 · app_role 24 · rate_limit 22 · models 14 · migrations 8 · scram 8 · db 3 · health 3 |
| Line + branch coverage (`backend/app`), with PostgreSQL | **97.40%** (983 statements, 22 missed; 134 branches, 7 partial; gate: 80%) |
| Line + branch coverage, without a database | 85.50% |
| Python files in `backend/app` | 47 (25 with code, 22 placeholders) |
| Lines in `backend/app` | 1,950 total (`wc -l`); 1,519 non-blank, non-comment |
| Tests | 16 Python files in `backend/tests` (13 test modules), 2,262 lines |
| Migrated schema | **7** tables, **6** enum types, **11** CHECK, **8** foreign-key, **4** unique constraints, **21** indexes, **1** trigger (3 migrations) |
| ruff check / ruff format | All checks passed / 64 files already formatted |
| mypy | No issues in 63 source files |
| bandit (`app/`) | No issues (0 high, 0 medium, 0 low) over 1,519 lines |
| pip-audit (`requirements.txt`, strict) | No known vulnerabilities |
| npm audit | 0 vulnerabilities |
| oxlint | exit 0, no findings |
| Frontend build | succeeded (Vite, built in 138 ms) |
| Image `aegis-backend` | 433 MB (`docker image ls`) · 93.8 MB (`docker image inspect .Size`) · `USER 10001:10001` |
| Image `aegis-frontend` | 97.1 MB (`docker image ls`) · 27.9 MB (`docker image inspect .Size`) · `USER 101` |
| Runtime process uids | backend 10001 · frontend 101 · nginx 101 · postgres 70 · redis 999 (no root processes) |
| Full stack, fresh volume | `migrate` exited 0 after applying all 3 revisions; backend healthy; `GET /api/health` via the edge → `200 {"status":"ok"}` |
| Live auth flow via the edge | register 201 → login 200 → `/me` 200 → refresh 200 → reuse of old refresh 401 → old access token 401; logout 204 → its access token 401 ([details](#proof-refresh-token-reuse-revokes-the-session-family)) |
| Edge login limit, 10 rapid `POST /api/v1/auth/login` | 5 × `401 application/json`, then 5 × `429 text/html` (nginx) |
| App auth limit, rapid `POST /api/v1/auth/refresh` | after 5 in the window: `429 application/json`, `Retry-After: 42` |
| CI jobs defined | 4 (`secret-scan`, `backend`, `frontend`, `containers`; `containers` is a 2-way matrix) |
| **CI run** ([40835243200](https://github.com/yp012/aegis/actions/runs/40835243200), commit `c95789a`, 2026-10-29) | **success: 5 of 5 job runs green** |
| CI backend pytest (against a `postgres:16` service) | `253 passed in 14.17s`; coverage 97.40% |
| CI backend static analysis | ruff: all checks passed · format: 64 files already formatted · mypy: no issues in 63 source files · bandit: no issues identified · pip-audit: no known vulnerabilities |
| CI frontend | oxlint: 0 warnings and 0 errors · build succeeded · npm audit: 0 vulnerabilities |
| CI Trivy v0.70.0 (`ignore-unfixed`, HIGH/CRITICAL) | backend image (Debian 12.15) and its Python packages: 0 · frontend image (Alpine 3.24.2): 0 · Dockerfile config scans: 0 for both |
| CI non-root image check | passed for both images (frontend reported `Configured user: 101`) |
| CI gitleaks 8.24.3 | no leaks found (1 commit scanned) |

### History

| Commit | Date | Tests (with DB / without DB) | Coverage | CI |
| --- | --- | --- | --- | --- |
| `ea88255` foundation | 2026-10-27 | n/a | n/a | [failed](https://github.com/yp012/aegis/actions/runs/40603048140): gitleaks flagged a dummy key hardcoded in the workflow, and `trivy-action@0.28.0` no longer resolved after the action's tags were migrated following a supply-chain attack. A local reproduction also found 58 fixable HIGH/CRITICAL CVEs in the old `nginx-unprivileged:1.27-alpine` base. All were fixed in `65b0112`. |
| `65b0112` CI fixes | 2026-10-27 | 70 / 62 + 8 skipped | 98.98% | [run 40604518785](https://github.com/yp012/aegis/actions/runs/40604518785): 5/5 green, `70 passed in 1.85s` |
| `ba2ac5c` restricted app role | 2026-10-29 | 114 / 82 + 32 skipped | 99.12% | [run 40832125599](https://github.com/yp012/aegis/actions/runs/40832125599): success |
| `c95789a` authentication | 2026-10-29 | 253 / 196 + 57 skipped | 97.40% | [run 40835243200](https://github.com/yp012/aegis/actions/runs/40835243200): 5/5 green, `253 passed` |

On `65b0112` (2026-10-27) the edge rate limit was also observed with 100 parallel
`GET /api/health` requests: 45 × 200, 55 × 429 (timing-dependent, not a benchmark). That was
before the app-level limiter existed and was not repeated.

### How these were measured

```bash
# Tests and coverage (from backend/)
.venv/bin/pytest --cov -q                                             # without DB
CI=true .venv/bin/pytest -q                                           # CI mode without DB
AEGIS_TEST_DATABASE_URL=postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis_test \
  .venv/bin/pytest --cov -q                                           # with DB (container above)
AEGIS_TEST_DATABASE_URL=… .venv/bin/pytest -m integration -q
.venv/bin/pytest --collect-only -q | grep '::' | sed 's/::.*//' | sort | uniq -c   # per module

# Static analysis (from backend/ and frontend/)
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy app tests
.venv/bin/bandit -c pyproject.toml -r app
.venv/bin/pip-audit -r requirements.txt --strict
npx oxlint; npm audit; npm run build

# Code size (from backend/)
find app -name '*.py' | wc -l
find app -name '*.py' -print0 | xargs -0 cat | wc -l
find app -name '*.py' -print0 | xargs -0 cat | grep -cvE '^\s*$|^\s*#'
for f in $(find app -name '*.py'); do [ "$(grep -cvE '^\s*$|^\s*"""|^\s*#' "$f")" -eq 0 ] && echo "$f"; done | wc -l   # placeholders
find tests -name '*.py' | wc -l; find tests -name '*.py' -print0 | xargs -0 cat | wc -l

# Schema counts (psql against the test container after `alembic upgrade head`)
SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename<>'alembic_version';
SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
  WHERE n.nspname='public' AND t.typtype='e';
SELECT contype, count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
  WHERE n.nspname='public' GROUP BY contype;               -- c=check, f=fk, u=unique
SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND tablename<>'alembic_version';
SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal;

# Full stack (Quick start steps, throwaway env file and project name)
docker compose -p aegisreadme --env-file <generated env> up -d --build
docker image ls --format '{{.Repository}} {{.Size}}'
docker image inspect -f '{{.Config.User}} {{.Size}}' <backend image> <frontend image>
docker exec <container> sh -c 'for p in /proc/[0-9]*; do awk "/^Uid:/{print \$2}" $p/status; done' | sort -u

# Auth flow and rate limits (through the edge)
curl -s -c jar -H 'Content-Type: application/json' -d '{…}' http://localhost:8080/api/v1/auth/login
curl -s -b jar -c jar -X POST http://localhost:8080/api/v1/auth/refresh      # then replay an older jar
for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code} %{content_type}\n' \
  -H 'Content-Type: application/json' -d '{"email":"nobody@example.com","password":"x"}' \
  http://localhost:8080/api/v1/auth/login; done | sort | uniq -c
redis-cli -a "$REDIS_PASSWORD" --no-auth-warning --scan --pattern 'aegis:*'   # inside the redis container

# CI results (per-job logs of the GitHub run)
gh run list --branch main --limit 5
gh run view 40835243200 --json jobs --jq '.jobs[] | "\(.name) | \(.conclusion)"'
gh run view 40835243200 --log --job <job-id> | grep -E 'passed|Total coverage|no leaks|vulnerabilities'

# CI jobs: top-level keys under `jobs:` in .github/workflows/devsecops.yml
```

---

## Roadmap (not yet implemented)

| Feature | Status |
| --- | --- |
| Zone access policy engine (active ∧ clearance ∧ unexpired grant) | Not started. `Clearance.satisfies()`, `ZoneAccessGrant.is_valid_at()` and `require_clearance` exist |
| RBAC (Admin / SecurityOfficer / Personnel) on domain endpoints | Building blocks done (`require_roles`, `require_clearance`); no domain endpoints exist to apply them to |
| Audit hash-chain writer and verifier | Not started. Append-only table and trigger exist |
| Audit events for auth (login success/failure, lockout, MFA, logout, token reuse) | Not started. Depends on the hash-chain writer |
| Access-event logging | Not started. `access_events` table exists |
| HMAC-SHA256 signed, time-bound visitor badges (QR) | Not started. `badges` table and `BADGE_HMAC_SECRET` exist |
| REST API: users, zones, visitors, badges, audit, dashboard | Not started. Auth routes are live; the other v1 modules are placeholders |
| Pydantic request/response schemas for the domain | Auth and user schemas done; 5 placeholder modules |
| Closed bootstrap (setup token or CLI-only first Admin) | Not started. Registration is open while no user exists |
| JSON 429 from the edge (`error_page 429` returning JSON with `Retry-After`) | Not started. nginx returns its default HTML page |
| Password change, MFA disable/recovery, Admin unlock/reset | Not started |
| React UI (login, zones, visitors, audit viewer, dashboard) | Scaffold. Health status page only |
| Demo data seed script (`make seed`) | Not started. Target exits with "not implemented yet" |
| Benchmark script (`make bench`) | Not started. Target exits with "not implemented yet" |

---

## Resume bullets

- Designed the PostgreSQL data layer for a zero-trust access-control portal with FastAPI and
  SQLAlchemy 2.x: 7 tables, 6 native enum types, 11 CHECK constraints and 8 foreign keys
  with per-relation delete semantics. Shipped it as hand-reviewed, reversible Alembic
  migrations whose downgrade/upgrade round-trip is covered by an automated test.
- Built the authentication layer: Argon2id hashing with timing-equalised failures, pinned-
  algorithm JWTs, refresh-token rotation with reuse detection that revokes the whole session
  family, a Redis access-token blacklist, Fernet-encrypted TOTP MFA with replay protection,
  account lockout, and an atomic Redis sliding-window rate limiter that fails closed on auth
  routes and trusts `X-Forwarded-For` only from the pinned edge proxy. 253 passing tests
  (57 against real PostgreSQL) at 97.40% coverage, green in CI.
- Enforced audit-log immutability at the database layer with a statement-level trigger that
  blocks UPDATE, DELETE and TRUNCATE. The API runs as a least-privileged PostgreSQL role
  that can only SELECT/INSERT the audit table and cannot disable the trigger, drop the table,
  or enable replica mode (verified via psql and 24 integration tests). Also built fail-fast
  config that rejects weak, placeholder or malformed secrets without echoing them.
- Containerised a 5-service stack where every process runs non-root, with capabilities
  dropped and read-only filesystems on the app and edge containers, an internal-only data
  network, and an Nginx edge with CSP and rate limiting. Built a 4-job GitHub Actions
  DevSecOps pipeline (gitleaks, ruff, mypy, bandit, pip-audit, npm audit, Trivy) that runs
  green on `main`, including PostgreSQL integration tests. Its last run found 0 leaks,
  0 bandit issues, 0 known vulnerable dependencies and 0 fixable HIGH/CRITICAL image CVEs.
  Third-party actions are pinned to commit SHAs.
