# Changelog

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
