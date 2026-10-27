# CLAUDE.md

## Project

**Aegis: Zero-Trust Access Control & Clearance Management Portal** — a portfolio-grade
cybersecurity full-stack application.

## Stack

- **Backend:** FastAPI + SQLAlchemy 2.x + Pydantic v2 + Alembic (Python 3.12)
- **Database:** PostgreSQL 16
- **Cache / ephemeral state:** Redis 7
- **Frontend:** React + Vite + TypeScript + Tailwind
- **Edge:** Nginx reverse proxy
- **Containers:** Docker multi-stage builds, non-root images
- **CI/CD:** GitHub Actions DevSecOps pipeline

## Rules (apply to every task)

- No placeholders, no TODOs, no stub functions. Every file must be complete and runnable.
- All secrets come from environment variables (pydantic-settings); never hardcode secrets.
  Provide `.env.example` only.
- Use constant-time comparison (`hmac.compare_digest`) for every secret/signature check.
- Type hints everywhere; code must pass `ruff check` and `mypy` (non-strict is OK).
- After finishing each task, run the relevant tests/linters and fix failures before
  reporting back.
- Do not run `git commit` or `git push`; the user does that themselves.

## Domain model summary

- **Roles:** `Admin`, `SecurityOfficer`, `Personnel`
- **Clearance tiers (ordered):** `Reliability` (1) < `Secret_Level_II` (2) < `Top_Secret` (3)
- **Zones** each have a `min_clearance`. Access is granted only if:
  - `user.is_active`, **and**
  - `user.clearance >= zone.min_clearance`, **and**
  - a `ZoneAccessGrant` exists for the user/zone and is unexpired.
- **Audit log** is an append-only SHA-256 hash chain.
- **Visitor badges** are HMAC-SHA256 signed, time-bound QR payloads.

## Reporting Requirements

After every task, end the reply with a **"Change Report"** containing:

1. **Files created:** list each path with a one-line description of its purpose.
2. **Files modified:** list each path and summarize what changed and why.
3. **Files deleted or renamed:** list them (or "none").
4. **Commands run:** the key commands (installs, migrations, tests, builds) and whether
   each succeeded or failed.
5. **Verification results:** exact test counts (passed/failed), coverage %, lint/type-check
   status, and anything that could not be verified and why.
6. **Decisions and trade-offs:** any design choice made that wasn't specified in the
   prompt, and any deviation from the prompt (with the reason).
7. **Known issues or risks:** anything incomplete, flaky, or worth the user's review.
8. **Next step:** what the user should check or run before moving to the next prompt.

Be honest and specific. Never claim something passed unless it was actually run. If
something failed or was skipped, say so plainly rather than summarizing it as done.
