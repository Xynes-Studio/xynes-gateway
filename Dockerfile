# =============================================================================
# xynes-gateway — multi-stage Dockerfile
# =============================================================================
#
# H-1 (pioneer): canonical Bun service Dockerfile recipe for the
# MVP release (group-H of the 2026-05-13 release plan + the
# HEALTHCHECK-CONTRACT.md §5 stanza).
#
# Stages
#   base  — pinned `oven/bun:1` by digest; shared install context.
#   dev   — bind-mount-friendly target for the local docker-compose dev
#           stack (already used by xynes-infra/docker-compose.dev.yml).
#   prod  — hardened runtime: non-root, no devDependencies, no test or
#           docs payload, no `.env*` files, HEALTHCHECK wired against
#           the H-1 /health route.
#
# Deviations from the canonical group-H skeleton (operator decision A,
# see AGENTS.md H-1 verification block):
#   1. No `build` stage. xynes-gateway runs `src/index.ts` directly
#      through Bun's TS support — there is no compile/bundle step.
#   2. The TypeScript correctness gate runs in CI (group-M `ci.yml`,
#      `bun run typecheck`), NOT inside the Dockerfile. There are 196
#      lines of pre-existing TS errors on `develop` that H-1 inherits
#      but did not introduce (filed as H-1-FU-1; see DEVELOPER.md).
#      Gating the prod image on those would block every group-H story
#      behind a debt unrelated to Dockerfile hardening.
#   3. The healthcheck script uses Bun's built-in fetch instead of
#      `curl`, so the image needs no extra apt-get layer.
# =============================================================================

# ====================================================
# base — pinned by manifest-list digest
#   Using oven/bun:1-alpine to land the prod image under the < 200 MB
#   group-H size budget. Bun's binary is statically linked, so musl libc
#   (alpine) vs glibc (debian) is a no-op for our workload. This is the
#   canonical base for all backend H-* stories — H-2..H-7a clone this
#   digest.
# ====================================================
FROM oven/bun:1-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS base
WORKDIR /app
COPY package.json bun.lock ./

# ====================================================
# dev — bind-mounted source, hot reload
# ====================================================
FROM base AS dev
RUN bun install --frozen-lockfile
COPY . .
EXPOSE 4100
CMD ["bun", "--watch", "src/index.ts"]

# ====================================================
# prod — hardened runtime
# ====================================================
FROM oven/bun:1-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS prod
WORKDIR /app

# Non-root user (gid/uid 1001 matches the canonical H-* recipe so
# Compose/K8s manifests can rely on a stable runtime UID). Alpine ships
# busybox's `addgroup`/`adduser`, not the debian `groupadd`/`useradd`.
RUN addgroup -S -g 1001 xynes && \
    adduser  -S -u 1001 -G xynes -H xynes

# Build-time: install full deps so dependency resolution is verified
# (catches a stale `bun.lock`), then discard them and reinstall
# production-only. Keeping it in one RUN means devDependencies never
# persist into the final image layers. Typecheck is enforced in CI
# (group-M); see deviation #2 above for rationale.
COPY package.json bun.lock tsconfig.json ./
COPY eslint.config.mjs ./
COPY src ./src
COPY index.ts ./index.ts
RUN bun install --frozen-lockfile && \
    rm -rf node_modules && \
    bun install --production --frozen-lockfile && \
    rm -rf /root/.bun /tmp/* && \
    chown -R xynes:xynes /app

USER xynes
EXPOSE 4100

# Per HEALTHCHECK-CONTRACT.md §5 — start-period gives Bun ~15 s to load
# routes from platform.routes before the probe goes red.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD bun run healthcheck || exit 1

# Run Bun directly against the entrypoint. Env vars are passed in via
# Docker (`-e`, compose `environment:`, or K8s env), not via a file —
# the `start` script's `--env-file` wrapper is for local-dev only.
CMD ["bun", "run", "src/index.ts"]
