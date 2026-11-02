# Changelog

## 0.1.2 — 2026-11-02

Release plumbing, no behaviour change: the images are the same code as 0.1.1.

- **published to GHCR as well as Docker Hub** — `.github/workflows/ci.yml` pushes
  `ghcr.io/freekngdom/netguard{,-guard}` on a `v*` tag using `GITHUB_TOKEN` (no
  secret), and Docker Hub when `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` are set.
- the previous Docker Hub gate was `if: secrets.…` at **job** level, which GitHub
  Actions cannot evaluate — it would never have published. Now job-level `env` with a
  step-level `if:`.
- Forgejo mirror to `github.com/freekngdom/netguard` (push mirror, sync on commit).
- CI: a Forgejo run now fails if `VERSION`, `docker-compose.yml` and the README
  disagree about the tag (that drifted three times while publishing).

## 0.1.1 — 2026-11-01

- **guard: cover `docker0` and `docker_gwbridge` in the cross-bridge chain.** The
  bridge/subnet set was matched with `^br-`, so anything started with a bare
  `docker run` — i.e. everything on docker's default bridge, a whole /16 — was
  reachable from every other bridge while looking covered. Found by comparing against
  the rule set the retired trafficjam left behind, which did cover it. Macvlan/ipvlan
  networks still have no bridge interface and are still not covered (unchanged
  behaviour, now stated explicitly).
- tests: the guard fixture includes a `docker0` line and asserts the rule count, so
  this cannot regress silently.

## 0.1.0 — 2026-11-01

First release: the guard and the UI, packaged together.

- **guard** — one iptables chain per shared network in `DOCKER-USER` (src/dst
  allowlists, alias resolution every poll, drift detection) plus host-wide
  cross-bridge isolation in `raw/PREROUTING`. `enforce` and `observe` (LOG) modes.
- **live reload** — the config is re-read when its md5 changes; a bad edit is parsed in
  a subshell, validated, refused, and the running policy is kept. A policy removed from
  the file has its chain cleared.
- **published state** — `status.json` (schema v1) after every build and every poll:
  per-bus mode/allowlist/hook/rule counts, refusals, `DOCKER-USER` jumps, the
  cross-bridge summary, and the observe-mode flows read from the kernel ring buffer.
- **UI** — read-only view of all of the above, plus optional editing
  (`NETGUARD_WRITE=1`): create/edit/delete a policy, flip enforce/observe, and turn an
  observed flow into an allowlist entry.
- Images: `netguard` (unprivileged, uid 10001) and `netguard-guard` (host netns).
