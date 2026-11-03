# netguard

[![ci](https://git.3773512.xyz/TammyTran/netguard/actions/workflows/ci.yml/badge.svg)](https://git.3773512.xyz/TammyTran/netguard/actions)

**East-west firewall policy for docker networks — enforced by iptables, explained by a web UI.**

Docker's default model lets every container reach every other container on the host.
netguard gives each shared network a policy: *which containers may talk, in which
direction*, with a per-network chain in `DOCKER-USER`, plus host-wide cross-bridge
isolation. It can measure before it enforces, and it shows you what is actually
installed rather than what you meant.

Two pieces, one project:

```
   docker-net-guard (guard)                     netguard (UI)
   ─────────────────────────                    ─────────────
   host netns, NET_ADMIN/SYSLOG                 unprivileged, uid 10001
   reads   docker-net-guard.conf  (intent)      reads   docker-net-guard.conf
   writes  iptables chains                      reads   /state/status.json
   writes  /state/status.json     (truth)       reads   docker API (read-only)
                                                writes  docker-net-guard.conf  ← optional
```

The guard owns the firewall. The UI is a view of it — plus, if you turn it on, an
editor for the one file that defines the policy.

## Where this lives

| | |
|---|---|
| source | <https://git.3773512.xyz/TammyTran/netguard> — this repo; tags `v0.1.x` are releases |
| mirror | <https://github.com/freekngdom/netguard> — pushed from here on every commit |
| UI image | `hippocampus/netguard` (Docker Hub) and `ghcr.io/freekngdom/netguard` |
| guard image | `hippocampus/netguard-guard` (Docker Hub) and `ghcr.io/freekngdom/netguard-guard` |
| version | `0.1.5` (both images share `status.json` schema v1 and the config grammar) |

All four images are multi-arch (`linux/amd64` + `linux/arm64`) and pull anonymously
from either registry. One `v*` tag publishes both from GitHub CI: GHCR with
`GITHUB_TOKEN` (no secret), Docker Hub with the `DOCKERHUB_USERNAME` /
`DOCKERHUB_TOKEN` repository secrets — a repo without those still publishes GHCR and
skips the Docker Hub steps. (`make push` does the same from a workstation.)

One gotcha for a fork: **a GHCR package starts private even when the repo is public**,
so the first publish needs a one-time visibility change in the package settings before
an anonymous `docker pull` works.

---

## Quick start

**1. Host prerequisite.** Bridged traffic must be handed to iptables, or the rules are
silently inert:

```sh
modprobe br_netfilter
echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf
echo 'net.bridge.bridge-nf-call-iptables=1' | sudo tee /etc/sysctl.d/99-br-netfilter.conf
sudo sysctl --system
```

**2. Configure.** `config/docker-net-guard.conf` holds the policies; `config/buses.txt`
lists networks you want to see even when no policy covers them (you can also label a
network `netguard.bus=true` instead).

**3. Run.**

```sh
DOCKER_GID=$(stat -c %g /var/run/docker.sock) docker compose up -d
```

This pulls `hippocampus/netguard:0.1.5` and `hippocampus/netguard-guard:0.1.5`. To run
your own build instead, `make build` (same tags, so the compose file needs no edit) and
uncomment the `build:` lines.

Open <http://localhost:8080>. The dashboard lists every bus with its posture — enforce,
observe, or **open** — the members, and the chain as installed right now.

> The socket proxy reads your Docker socket; set `DOCKER_GID` as above so it can. Both
> containers speak only to a read-only, GET-only proxy — neither mounts the socket.

---

## Concepts

### bus

A docker network shared by more than one project (`proxy`, `backend`, `workers`…). A
stack-local network that compose creates per project is **not** a bus: it only ever
holds one project's containers, and the cross-bridge chain already isolates it.

### direction — the important part

One policy per bus, and it is **one-sided**. Pick the side that is the small set:

| you write | meaning |
|---|---|
| `edge src 10.10.10.0/24 traefik` | only `traefik` may **start** traffic on this bus. It can reach every member; nobody else can reach anything. |
| `backend dst 10.10.20.0/24 db:5432,cache:6379` | any member may start traffic, but **only to** `db` on 5432 and `cache` on 6379. |

The UI asks this as two sentences — *“only these apps may start traffic”* and *“anyone
may connect, but only to these apps”* — because those are the only two shapes a bus
policy can express. There is no way to say “A may reach B and nothing else” on a bus
with more members; give that pair its own network instead (one caller + one server, a
`--internal` network, an alias on each side).

### where a bus comes from — three sources, one union

A network is listed if **any** of these names it, and the three do *not* synchronise:

| source | what it does |
|---|---|
| a policy in `docker-net-guard.conf` | **enforces** it — this is the only input the guard reads |
| `config/buses.txt` (`<name> <subnet> [ip-range]`) | lists it, so an unguarded network is visible. Nothing is enforced |
| a `netguard.bus=true` label on the docker network | same as the file, resolved from the live network list |

The page takes the union at read time and says which sources each bus came from. For
the *displayed* subnet the order is: policy → live docker network → definition file.

Consequences worth knowing:

- **deleting a policy does not unlist the bus** — it becomes **open**, which is exactly
  what you want to see afterwards;
- **removing a definition does not unguard anything** (it never guarded anything) — the
  bus simply disappears from the list unless a policy covers it;
- the guard never sees `buses.txt` or a label: a bus listed that way is enforced by
  nothing;
- a definition naming a network docker does not have is flagged as a **stale entry**;
  a *policy* naming one is flagged as an error, because that chain matches nothing at
  all.

### mode

| mode | behaviour |
|---|---|
| `enforce` | conntrack replies, then allowlist, then **DROP** the rest of the subnet |
| `observe` | identical, but **LOG** each would-be-dropped flow and let it through |

Always add a bus as `observe`, watch its flow table for a day or two, then flip it.
The flow table is the evidence; it is published by the guard, because only the guard
can read the kernel ring buffer.

### names, not addresses

Allowlist entries are docker aliases (`db`, `cache`, `traefik`), re-resolved on every
poll. A recreated container changes address and the rule follows it. A literal IP is
supported for the one case where no container exists yet (a reserved address for a
backup agent, say) — and it will *not* follow anything.

An entry that resolves to nothing is **skipped**, and a policy whose whole allowlist
fails to resolve is **refused**: installing an empty allowlist would DROP the entire
bus, so the guard fails closed toward “leave it alone and complain”. That bus stays
**unfiltered** until the name resolves again — the UI marks it, and this is the single
most important thing to watch.

---

## The UI

- **List** — every bus with mode, member count, the rule in one line, and whether the
  chain is installed right now (from `status.json`, not from your config).
- **Bus** — the rule in plain English, the allowlist with each alias resolved to its
  address and container, members with their role, the live chain, and the observed
  would-be-dropped flows.
- **Widget endpoint** — `/api/widget` returns flat counters for a dashboard (homepage's
  `customapi` widget is the reference). `/api/state` returns the whole model.

Run it read-only and put your own authenticating reverse proxy in front: the page maps
your firewall. netguard has no auth of its own by design.

---

## Editing from the UI (optional)

Set `NETGUARD_WRITE=1` and any bus page grows **Edit rule** / **+ Add rule**. The
editor writes the same `docker-net-guard.conf` the guard sources:

- **it asks one question**, then shows the resulting rule and how many of the bus's
  member→member pairs it allows;
- **comments survive** — only the `POLICIES` block and the `MODES` line are rewritten;
- **it validates before writing**: the alias must exist on that bus, ports only make
  sense on the destination shape, the subnet comes from the live network, the new file
  is re-parsed, and the old one is backed up to `/data/backups` first;
- **it applies live** — the guard re-reads its config when the file's md5 changes, so
  no restart is needed (allow one poll interval);
- **it never commits**. The config is yours: the page shows the diff and you `git
  commit` it.

Stale-page protection is built in: if the file changed since you loaded the page, the
save is refused instead of overwriting the other edit. DELETE leaves the bus open, so
it asks first and says so.

---

## Security model

| | guard | UI |
|---|---|---|
| runs as | root in container (required to program the host ruleset) | uid 10001 |
| capabilities | `NET_ADMIN`, `NET_RAW`, `SYSLOG` | none |
| network | host (it *is* the host firewall) | one bridge + published port |
| docker access | read-only proxy (`GET /containers`) | read-only proxy (`GET`) |
| rootfs | read-only | read-only |
| can write | iptables; `/state/status.json` | `docker-net-guard.conf`; `/data` |

`SYSLOG` exists only to read would-be-dropped flows out of the kernel log
(`kernel.dmesg_restrict=1` denies an unprivileged read). It is strictly less privilege
than `NET_ADMIN`, and it lives in the guard so the UI needs nothing.

The editor is the only path that writes anything, it is off by default, it is confined
to one file, and a mistake there is a firewall change — which is why every write is
validated, backed up, and shown as a diff. POSTs require JSON and a same-origin
`Origin`; there is no CORS.

---

## Building and publishing

Both images are published under **`hippocampus/`** on Docker Hub — usernames there are
global, and the plain `netguard` namespace is not ours:

| image | what it is |
|---|---|
| `hippocampus/netguard` / `ghcr.io/freekngdom/netguard` | the UI, unprivileged, port 8080 |
| `hippocampus/netguard-guard` / `ghcr.io/freekngdom/netguard-guard` | the guard, host netns, NET_ADMIN/NET_RAW/SYSLOG |

```sh
docker login                       # hippo campus account + an access token, not a password
make build                         # or: make build OWNER=somebodyelse
make push                          # tags and pushes :0.1.5 and :latest for both
```

If `./guard` fails to build with `apk … temporary error (try again later)`, the build
container cannot resolve anything — see the Troubleshooting row above and use
`make push NETWORK=host`.

The first `push` creates the repositories (Docker Hub defaults to public). Then use
`image:` instead of `build:` in `docker-compose.yml`:

```yaml
  netguard-guard:
    image: hippocampus/netguard-guard:0.1.5
  netguard:
    image: hippocampus/netguard:0.1.5
```

Multi-arch — **what `0.1.5` is published as**: an OCI index with `linux/amd64` and
`linux/arm64`, so `docker pull` picks the right one (a Raspberry Pi works):

```sh
docker run --privileged --rm tonistiigi/binfmt --install arm64   # once, for emulation
make push-multiarch
```

`make push` stays single-arch for the arch you are on; the CI workflow publishes
multi-arch on a `v*` tag, to GHCR always and to Docker Hub when the two secrets exist.

GHCR by hand, if you want it before a tag:

```sh
echo "$GITHUB_TOKEN" | docker login ghcr.io -u freekngdom --password-stdin
docker tag netguard:0.1.5 ghcr.io/freekngdom/netguard:0.1.5 && docker push ghcr.io/freekngdom/netguard:0.1.5
```

### Mirroring

The source lives on Forgejo and is push-mirrored to GitHub on every commit
(`sync_on_commit`, no interval), the same way the other repos here are: repo settings →
Mirror Settings → add a push mirror pointing at the SSH URL, then add the generated
public key to the GitHub repository as a **deploy key with write access**. The keypair
is generated by that settings page — the API creates the mirror without one, so a
mirror added through the API cannot authenticate.

**CI publishing** needs two repository secrets: `DOCKERHUB_USERNAME=hippocampus` and
`DOCKERHUB_TOKEN` (Docker Hub → Account settings → Security → New access token, *Read
& Write*). With those set, pushing a `v*` tag builds and pushes both images; without
them the workflow still builds but does not push.

### Upgrading

The two images share `status.json` **schema v1** and the config grammar, so they are
interchangeable within a minor version:

- **UI alone** can be upgraded freely — an older guard simply publishes less (no
  `observed` block, and the page says so instead of inventing numbers).
- **Guard alone** can be upgraded freely — it writes the same schema; a `0.1.x` UI
  reads it.
- A **schema** bump (v2) would be a minor version for both, and an old UI would report
  `unsupported status schema` rather than misread it.
- Your config file is untouched by an upgrade: it is mounted, not owned by either image.

### Publishing to Docker Hub

The repositories were created by the first push, so their `description` and
`full_description` are empty — Docker Hub does not read the README. To fill them, edit
the repository on <https://hub.docker.com> (or `PATCH /v2/repositories/<user>/<repo>/`
with an access token). A one-paragraph blurb that fits both:

> East-west firewall policy for docker networks: one iptables chain per shared network
> with a src/dst allowlist, cross-bridge isolation, an observe mode that logs what a
> rule would cut, and a web UI that shows what is actually installed. Two images:
> `netguard-guard` (host netns) and `netguard` (unprivileged UI). Source:
> git.3773512.xyz/TammyTran/netguard

## Troubleshooting

| symptom | cause |
|---|---|
| a bus says **open** | no policy covers it — by design, or a typo in the name |
| a bus says **refused** | its allowlist resolved to nothing. Nothing is being enforced there; fix the alias |
| a container-to-container call **hangs** (no RST, no ICMP) | that is what a DROP looks like. Check the bus mode and allowlist before the app config |
| edits do not apply | the guard reloads within one poll; a syntax error is refused and the old policy kept — see the guard's logs |
| `observed.ok: false` | the guard cannot read the kernel log (no `SYSLOG`, or no `dmesg` in the image) |
| rules seem to do nothing | `br_netfilter` is not loaded, or `bridge-nf-call-iptables=0` |
| **same-bridge** traffic is dropped (`dial tcp …:5432: connection timed out` between two containers on one compose network) | a **stale** `DOCKERNET_XBRIDGE` left over from before a full `docker compose down`/`up`. The chain is deliberately never flushed (a stopped guard fails closed), and after a `down`/`up` every network returns on the same subnet with a **new** `br-<id>`, so the interface-based DROP was matching a bridge that no longer exists. Fixed in 0.1.4 by a same-subnet RETURN ahead of that DROP — a pre-0.1.4 chain still has this, so clear it once: `docker exec socket-net-guard iptables -t raw -D PREROUTING -j DOCKERNET_XBRIDGE; iptables -t raw -F DOCKERNET_XBRIDGE; iptables -t raw -X DOCKERNET_XBRIDGE` (with the guard **down**, or just restart it so it rebuilds) |
| `make build` fails in `./guard` with `apk add … temporary error (try again later)` and `no such package` | the **build container** has no DNS. It is not a problem with the packages: a host whose resolver lives inside a VPN namespace (WireGuard/NetBird/Tailscale) only answers from the host netns, and a default-bridge build container cannot reach it. Build with `make build NETWORK=host` (or `docker build --network host …`). Permanently: add `"dns": ["1.1.1.1"]` to `/etc/docker/daemon.json` and restart dockerd |
| flows missing from the observe table | an *established* flow rides the conntrack RETURN and is never logged; the LOG rules have no `--limit`, so a missing allowlist entry wraps the buffer quickly |

`docker exec netguard-guard iptables -S DOCKERNET_<bus>` shows one chain;
`cat state/status.json` shows what the guard believes.

---

## Tests

```sh
python3 -m pytest -q            # or: docker compose run --rm ... (no image for tests)
```

56 tests: config parse/render (comments survive, idempotent), validation and the write
path (backups, atomic replace, stale-page refusal, mode/delete/allow-flow), the HTTP
surface (including CSRF and content-type refusals), and the guard itself run against
**fake** iptables/ip/docker/dmesg — policy refusal, chain clearing on reload, the
cross-bridge rule **order** (the same-subnet RETURN must precede the interface DROP,
which is what keeps a stale bridge name from cutting a network off), and the
ring-buffer parser, including the truncation quirk below.

The parser detail worth knowing if you touch it: iptables truncates `--log-prefix` to
29 characters and `docker-net-guard/` is 17 of them, so a 12-character bus name
consumes the rest and the trailing `": "` is **cut** — the line reads
`docker-net-guard/downloadarrsIN=…`, with neither colon nor space. Cut at `IN=`, never
at `:`.

## License

MIT — see [LICENSE](LICENSE).
