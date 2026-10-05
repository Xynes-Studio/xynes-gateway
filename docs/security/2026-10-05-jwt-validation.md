# SEC-006 implementation and pre-PR revalidation

2026-10-05, `feature/security-audit-remaining-high-medium`. Local implementation/review pass; not merged, deployed or rotated. Ticket start: gateway `5c18c1608ad125856bd023c883f9b06d48754c6c`; develop base `68479be7db184332009eec1cc90a7e5bcc09ca5e`.

## Behavior and scope

A shared typed policy rejects missing/nonfinite/noninteger/string time claims, invalid subjects/audiences, future issuance/not-before, expired tokens and excessive total lifetime for both HS256 and RS256. Required `iat`/`exp`, optional `nbf` and zero clock-skew semantics are documented in DEVELOPER.md. Lifetime defaults to 3600 seconds and accepts explicit integer limits 60–86400. Environment parsing fails closed. Both gateway auth entry points forward the configured limit.

Production startup and token verification require exact issuer/audience configuration, regardless of the deprecated opt-out flag. Existing dev-only missing-context warnings remain. Subject values cannot be coerced from objects. JWT errors use a generic message.

Reviewer fixes: remove unsafe JSON/JWKS assertions, reject malformed key entries/identifiers and ambiguous multiple matching keys during rotation, preserve consistent option/config lifetime precedence, test startup logging and correct template issuer guidance. RSA test-key export assertions were replaced with typed exports. Ordinary historical fixtures gained issuance times and current bounded expiries; negative security fixtures use an independent raw signer so missing claims are not silently filled.

No dependency, lockfile, database or route-contract change. Existing algorithm support remains HS256/RS256. Canonical fixtures match the required claims in the primary [Supabase JWT fields documentation](https://supabase.com/docs/guides/auth/jwt-fields); they prove verifier compatibility, not hosted login acceptance.

## Evidence

- Baseline: 695 passing tests from SEC-003 checkpoint. Six initial policy tests failed four cases before the implementation, then passed. New boundary/production/key-rotation tests pass.
- `NODE_ENV=test XYNES_ENV_FILE=/private/tmp/xynes-security-goal/test.env DATABASE_URL=postgresql://fixture:fixture@127.0.0.1:1/security_fixture bun run coverage`: **707 pass, 0 fail**, 1988 assertions, 48 files. Overall **95.90% functions / 96.22% lines**.
- Changed instrumented files (functions / lines): `security/jwtPolicy.ts` **100 / 100**; `security/jwtStartupWarnings.ts` **100 / 100**; `utils/jwt.ts` **96 / 94.93**; `middleware/jwtAuth.ts` **100 / 86.67**; `router/dynamicRouter.ts` **87.50 / 99.42**; `testUtils/jwtTestUtils.ts` **100 / 100**. All meet the 80% floor. Config module is mocked by the full suite; the isolated smoke exercises its real environment parsing and forwarding without claiming fabricated coverage.
- `bun run typecheck`: pass, including the smoke script. `bun run lint`: pass with 33 existing test-only `any` warnings; no new suppression or compiler relaxation. `git diff --check`: pass. No separate formatter/build script is configured; the applicable runtime build is the production Docker target.
- `bun scripts/test/jwt-production-smoke.ts`: pass using actual config/middleware, ephemeral keys, production context and a 60-second configured limit. Rejects malformed, expired, overlong and wrong-context HS256 tokens; accepts valid HS256/RS256 and verifies mandatory startup guard. No DB/provider/network access or env-file loading.
- `docker build --target prod -t xynes-security-sec006-gateway:local .`: pass. Final image identifier is recorded in infra's revalidation report. `docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount type=bind,src=<gateway>/scripts/test,dst=/app/scripts/test,readonly --entrypoint bun xynes-security-sec006-gateway:local scripts/test/jwt-production-smoke.ts`: pass under the image's non-root `xynes` user. This is a verifier/middleware smoke, not a live DB-backed service health check.
- Infra env-template no-secret gate: **148/148** assertions pass. Hosted templates now require the exact stage issuer, with inert `.invalid` placeholders.

Logs: `/private/tmp/xynes-security-goal/sec006-*.log`. Shell/Docker/docs are validated by execution and inspection, without invented coverage. No hosted environment or real credentials were changed.

## Remaining acceptance and rollout

Implementation and explicit pre-PR review pass the ticket's malformed/context-mismatch requirements. The independently verifiable repository work is ready for the later combined PR. Hosted configuration verification, deployment, login/refresh smoke and real signing-key rotation are unperformed external acceptance requirements.

The sibling infra repository contains `infra/release/JWT-VALIDATION-ROLLOUT.md` with exact issuer/lifetime migration, 180-day/emergency rotation, single-key HS256/static-RSA cutovers, distinct JWKS identifiers/cache overlap and emergency cache clearing. These goal records are local/unpublished; do not fabricate GitHub links before publication. Reducing lifetime or tightening claims can invalidate prior tokens; coordinate provider settings and login refresh. Rollback to the old verifier reopens the finding and requires explicit operational authorization.
