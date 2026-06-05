## Summary
<!-- One-paragraph description of what this PR does and why. -->

## Linked work
- Plan / issue: <!-- link -->
- Related repos: <!-- link any PRs that depend on or are depended on by this one -->

## Quality gates
- [ ] `lint` passes locally
- [ ] `test` passes locally
- [ ] Coverage ≥ ADR-001 80% floor (or justified exception below)
- [ ] `typecheck` / `build` passes (where applicable)
- [ ] Docs updated (`README.md`, `DEVELOPER.md`, `AGENTS.md`, repo memory)
- [ ] Migration added (if schema change) — forward-only, expand/contract
- [ ] QA PII scrub updated (if migration adds PII)
- [ ] Release doc set updated (if release contract changed)

## Security
- [ ] No secrets in code, logs, error messages, or test fixtures
- [ ] No raw API keys forwarded to downstream services
- [ ] No PII added to telemetry or access logs

## Deployment notes
<!-- e.g. "Requires migration run before service rollout", "Requires xynes-platform-contracts vX.Y.Z first". -->

## Rollback plan
<!-- For risky changes only. -->

---

## Repo-specific items (xynes-gateway)

This is a **Bun + Hono** service. Use `bun`, never `npm`.

- [ ] Lint: `bun run lint` (eslint over `src/**/*.ts`)
- [ ] Tests: `bun run test` (bun test)
- [ ] Coverage: `bun run coverage` — overall must stay at or above the **ADR-001 80% lines + branches floor**
- [ ] Typecheck: `bun x tsc --noEmit` — zero new errors vs the target branch baseline (verify with `git stash` round-trip if pre-existing errors exist)
- [ ] Gateway is **fail-closed and DB-backed** — every dynamic route comes from `platform.routes`. PRs that add a new downstream service must include the corresponding route seed in `xynes-infra/supabase/migrations/20251229100001_seed_platform_routes.sql` (or a successor) AND wire the service into `src/router/dynamicRouter.ts`. Confirm the service-key allowlist + `/internal/<service>-actions` action endpoint construction are both updated.
- [ ] Any change to the redaction surface (`src/logging/redaction.ts`, `src/telemetry/sanitize.ts`, `src/telemetry/types.ts`) must extend the regression sweeps so raw API keys (`xynes_live_<hex>`, `re_<hex>`, `AKIA[A-Z0-9]+`, `X-Amz-Signature=*`) cannot leak through telemetry payloads or access-log snippets.
- [ ] If touching `DATABASE_URL` / startup contract: gateway MUST fail-fast when the env var is missing, the DB fetch fails, or `platform.routes` is empty. Do NOT relax this posture.
