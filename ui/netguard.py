#!/usr/bin/env python3
"""netguard — a web front-end for docker-net-guard.

WHAT THIS IS
  docker-net-guard enforces east-west policy between docker networks on one host:
  one iptables chain per guarded network, plus a cross-bridge chain. It has no API
  and no database. Its state lives in three places, and this app reads all three
  and renders them as one page:

    1. docker-net-guard.conf   the INTENT (POLICIES/MODES), a shell file the guard
                               sources. Parsed here with the same grammar, and —
                               when editing is enabled — rewritten by this app.
    2. guard status.json       the LOADED state, published by the guard after every
                               build and every poll: per-bus mode, resolved
                               allowlist, hook presence, rule counts, refusals,
                               observe-mode flows, DOCKER-USER jumps, cross-bridge
                               counts.
    3. the docker API          MEMBERSHIP: which container is on which network, its
                               address and its aliases (read-only).

WHY IT EXISTS
  Answering "which networks are guarded, how, and is that actually installed right
  now?" otherwise means reading a shell config, `docker exec`-ing for `iptables -S`,
  and remembering that an allowlist which resolves to nothing leaves a network
  UNFILTERED — the guard refuses such a policy rather than dropping the whole bus.

WHAT IT DOES NOT DO
  * no per-flow probing: it reports policy and observed drops, not liveness
  * no docker writes: the Engine API is read-only, and the only file it ever writes
    is the guard's own config (and only when NETGUARD_WRITE=1)
  * no auth of its own: put a reverse proxy with authentication in front of it

EDITS ARE OPT-IN
  With NETGUARD_WRITE=1 the page can create, change and delete a network's policy.
  It validates first, backs the old file up, re-parses what it is about to write,
  and applies atomically. It never commits anything: the config file is yours.

ENV
  DOCKER_HOST       tcp://docker-socket-proxy:2375   read-only Engine API
  GUARD_CONF        /guard/docker-net-guard.conf      the config it reads and edits
  GUARD_STATE_DIR   /state                            where the guard publishes status
  BUSES_FILE        /guard/buses.txt                  optional network definitions
  SHARED_NETS_FILE  (legacy) a script with `create <name> <subnet> <range>` lines
  BACKUP_DIR        /data/backups                     pre-write config backups
  GUARD_CONTAINER   netguard-guard                    container name, for liveness
  NETGUARD_WRITE    0                                 "1" enables editing
  LISTEN            0.0.0.0:8080
  STATE_TTL         30   seconds to cache docker API reads
  GOOD_TTL          90   seconds to serve the last good read after an API failure
"""

from __future__ import annotations

import difflib
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import sys
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.3"

# ─── configuration ────────────────────────────────────────────────────────────
DOCKER_HOST = os.environ.get("DOCKER_HOST", "tcp://docker-socket-proxy:2375")
GUARD_CONF = os.environ.get("GUARD_CONF", "/guard/docker-net-guard.conf")
GUARD_STATE_DIR = os.environ.get("GUARD_STATE_DIR", "/state")
# Where the list of networks comes from. `buses.txt` is the generic input:
#     <name> <subnet> [<ip-range>]
# Networks may also opt in with a docker label (netguard.bus=true), which needs no
# file at all. SHARED_NETS_FILE is the legacy form this project grew from: a shell
# script with `create <name> <subnet> <ip-range>` lines.
BUSES_FILE = os.environ.get("BUSES_FILE", "/guard/buses.txt")
SHARED_NETS_FILE = os.environ.get("SHARED_NETS_FILE", "")
BUS_LABEL = os.environ.get("BUS_LABEL", "netguard.bus")
LISTEN = os.environ.get("LISTEN", "0.0.0.0:8080")
STATE_TTL = float(os.environ.get("STATE_TTL", "30"))
GUARD_CONTAINER = os.environ.get("GUARD_CONTAINER", "netguard-guard")
TZ = os.environ.get("TZ", "America/Los_Angeles")

# iptables truncates --log-prefix to 29 characters, and the prefix is
# "docker-net-guard/<bus>: " — 19 characters of overhead, so a bus name longer
# than 12 characters is cut short in the LOG (`homepage_widgets` arrives as
# `homepage_wid`). Nothing else in the rule carries the name, so match on that.
LOG_PREFIX_OVERHEAD = 19
LOG_NAME_BUDGET = 29 - LOG_PREFIX_OVERHEAD

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def log(msg: str) -> None:
    sys.stderr.write("[netguard] %s\n" % msg)


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


# ─── docker API (read-only socket proxy) ──────────────────────────────────────
class DockerError(Exception):
    """A failed Engine API call.

    `status` is the HTTP code the proxy returned, or None when the request never got
    an answer (connection refused, timeout). The distinction matters: a 404 is a
    fact about a container ("it is not there") and may be cached, while a transport
    error is a fact about the READER and must never be cached as "absent" — that is
    how a one-second proxy restart used to become a minute of "guard is down" and
    fourteen fake allowlist findings.
    """

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class Docker:
    """Minimal Engine API client over the read-only socket proxy.

    The proxy is name-allowlisted (SP_ALLOWFROM) and only permits GET, so a call
    that is not in SOCKET_PROXY_APPS is refused with 403 rather than reaching the
    daemon — which is exactly the failure this app should NOT swallow silently.
    """

    def __init__(self, spec: str):
        m = re.match(r"^tcp://([^:/]+):(\d+)$", spec)
        if not m:
            raise DockerError("DOCKER_HOST must look like tcp://host:port (got %r)" % spec)
        self.host, self.port = m.group(1), int(m.group(2))

    def get(self, path: str):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            # docker-socket-proxy forwards to the unix socket; the Host header is
            # irrelevant to dockerd but some proxies sanity-check it.
            conn.request("GET", path, headers={"Host": "docker"})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status >= 400:
                raise DockerError("GET %s -> HTTP %d" % (path, resp.status), status=resp.status)
            return json.loads(body or b"null")
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError("GET %s -> %s" % (path, exc)) from exc
        finally:
            conn.close()


DOCKER = Docker(DOCKER_HOST)

_cache: dict[str, tuple[float, object]] = {}


def cached(key: str, fn):
    expires, value = _cache.get(key, (0.0, None))
    if expires > time.time():
        return value
    value = fn()
    _cache[key] = (time.time() + STATE_TTL, value)
    return value


def docker_networks() -> list[dict]:
    return cached("networks", lambda: DOCKER.get("/networks") or [])


def docker_containers() -> list[dict]:
    # /containers/json already carries NetworkSettings.Networks with each
    # endpoint's Aliases, so membership + aliases need ONE call. Do not switch to
    # /networks/{id}: docker reports an EMPTY Containers[].Aliases there, which is
    # the trap documented in the README (network inspect reports no aliases).
    return cached("containers", lambda: DOCKER.get("/containers/json") or [])


def docker_inspect(name: str) -> dict | None:
    """One container's full state (RestartCount, State). `None` when it does not exist.

    A 404 is cached as "absent" (it must not be re-queried on every page load); a
    transport error is RAISED, because the caller has to be able to tell "this
    container is gone" from "I could not ask", and caching the second as the first
    pins a wrong answer for the whole TTL.
    """
    key = "inspect:%s" % name
    expires, value = _cache.get(key, (0.0, None))
    if expires > time.time():
        return value
    try:
        value = DOCKER.get("/containers/%s/json" % name)
    except DockerError as exc:
        if exc.status == 404:
            _cache[key] = (time.time() + STATE_TTL, None)
            return None
        raise
    _cache[key] = (time.time() + STATE_TTL, value)
    return value


# ─── config parsing ───────────────────────────────────────────────────────────
def shell_var(text: str, name: str) -> str:
    """Extract  NAME="..."  from the guard's shell config.

    The file is POSIX sh and is sourced by the guard rather than parsed, because
    the guard image has no python/jq. Reading it here must therefore cope with the
    two shapes the file uses: a one-line value (MODES) and a multi-line block
    (POLICIES), both quoted. Comments and anything else are ignored.
    """
    m = re.search(r"^[ \t]*%s=\"(.*)$" % re.escape(name), text, re.M)
    if not m:
        return ""
    first = m.group(1)
    if first.endswith('"'):
        # `NAME="value"` on one line — including the empty `NAME=""`, whose captured
        # value is just the closing quote.
        return first[:-1]
    out = [first]
    for line in text[m.end():].splitlines():
        if line.strip() == '"':
            break
        out.append(line)
    return "\n".join(out)


def read_guard_conf() -> dict:
    try:
        with open(GUARD_CONF, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return {
            "ok": False,
            "error": "cannot read %s: %s" % (GUARD_CONF, exc),
            "policies": [],
            "modes": {},
            "md5": "",
        }
    return parse_conf_text(text)


def parse_conf_text(text: str) -> dict:
    """Parse the guard's shell config. Shared by the reader and the editor, so a
    written file is validated by exactly the parser that renders it."""
    policies = []
    block = shell_var(text, "POLICIES")
    if not block.strip():
        return {
            "ok": False,
            "error": "no POLICIES block in the config",
            "policies": [],
            "modes": {},
            "md5": hashlib.md5(text.encode()).hexdigest(),
        }
    tokens = block.split()
    if len(tokens) % 4:
        return {
            "ok": False,
            "error": "POLICIES has %d fields — not a multiple of 4" % len(tokens),
            "policies": [],
            "modes": {},
            "md5": hashlib.md5(text.encode()).hexdigest(),
        }
    for i in range(0, len(tokens), 4):
        name, direction, subnet, allow = tokens[i : i + 4]
        policies.append(
            {
                "name": name,
                "dir": direction,
                "subnet": subnet,
                "allow": allow,
                "entries": [e for e in allow.split(",") if e],
            }
        )

    modes = {}
    for item in shell_var(text, "MODES").split(","):
        item = item.strip()
        if not item:
            continue
        name, _, mode = item.partition(":")
        modes[name] = mode or "enforce"

    return {
        "ok": True,
        "error": None,
        "policies": policies,
        "modes": modes,
        "md5": hashlib.md5(text.encode()).hexdigest(),
    }


def read_shared_defs() -> dict:
    """Networks to list even when no policy covers them.

    The guard's config cannot supply this: an unguarded network is absent from it by
    definition, and those are exactly the ones worth seeing. Three sources, merged:

      * BUSES_FILE — `<name> <subnet> [<ip-range>]`, `#` comments
      * docker labels — `netguard.bus=true`, resolved from the live network list
      * SHARED_NETS_FILE — legacy `create <name> <subnet> <ip-range>` script lines
    """
    out: dict[str, dict] = {}

    def add(name: str, subnet: str, ip_range: str, internal: bool, source: str) -> None:
        out[name] = {
            "name": name,
            "subnet": subnet,
            "ip_range": ip_range,
            "internal": internal,
            # every definition source that names this network, so the page can say
            # why a bus is listed. A set: a network can be in the file AND labelled.
            "sources": {source},
        }

    if BUSES_FILE:
        try:
            with open(BUSES_FILE, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        log("%s: ignoring %r (want <name> <subnet> [ip-range])" % (BUSES_FILE, line))
                        continue
                    add(parts[0], parts[1], parts[2] if len(parts) > 2 else "", "internal" in parts[3:], "file")
        except FileNotFoundError:
            pass
        except OSError as exc:
            log("cannot read %s: %s" % (BUSES_FILE, exc))

    if SHARED_NETS_FILE:
        try:
            with open(SHARED_NETS_FILE, "r", encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r"^\s*create\s+(\S+)\s+(\S+)\s+(\S+)(.*)$", line)
                    if m:
                        add(m.group(1), m.group(2), m.group(3), "--internal" in m.group(4), "file")
        except OSError as exc:
            log("cannot read %s: %s" % (SHARED_NETS_FILE, exc))
    return out


def read_status() -> dict | None:
    path = os.path.join(GUARD_STATE_DIR, "status.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log("cannot read %s: %s" % (path, exc))
        return None


# ─── observe-mode evidence ────────────────────────────────────────────────────
# ─── model ────────────────────────────────────────────────────────────────────
def is_ipv4(value: str) -> bool:
    return bool(IPV4_RE.match(value))


def split_entry(entry: str) -> tuple[str, str | None]:
    """`<alias>`, `<alias>:<port>`, `<ip>`, `<ip>:<port>`, `<ip>:*` -> (target, port)."""
    if ":" in entry:
        target, _, port = entry.rpartition(":")
        if target:
            return target, port
    return entry, None


def ip_in_subnet(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def expand_entry(resolved: dict) -> list[str]:
    """What the guard would put in the chain for one allowlist entry.

    Deliberately mirrors expand_allowlist(): a literal is passed through verbatim
    (so `10.70.2.200:*` stays `10.70.2.200:*`), an alias becomes its address plus
    `:port` only when the entry named a port. Comparing like for like is what makes
    "installed differs from resolved" a meaningful warning instead of noise.
    """
    if resolved["status"] == "literal":
        return [resolved["entry"]]
    if not resolved["ips"]:
        return []
    if resolved["port"] and resolved["port"] != "*":
        return ["%s:%s" % (ip, resolved["port"]) for ip in resolved["ips"]]
    return list(resolved["ips"])


def normalize(entries: list[str]) -> str:
    """Same canonical form the guard compares against (sorted, comma-joined)."""
    return ",".join(sorted(e for e in entries if e))


def guard_state(status, status_age, container_running, docker_error) -> str:
    """up | stale | down | unknown | no status — from the guard's OWN heartbeat.

    status.json is rewritten every poll, so a fresh one proves the process is alive
    even when the Docker API cannot be reached. The container list is a secondary
    hint used only when the heartbeat is old, and "I could not ask" is never
    reported as "it is down" — that inversion is what turned a one-second
    socket-proxy restart into a dashboard claim that the firewall was gone.
    """
    if status is not None and status_age is not None:
        poll = float(status.get("poll_interval") or 60)
        if status_age <= 3 * poll:
            return "up"
        if docker_error:
            return "unknown"
        return "down" if container_running is False else "stale"
    if docker_error:
        return "unknown"
    return "down" if container_running is False else "no status"


_LAST_GOOD: dict = {"at": 0.0, "model": None}
GOOD_TTL = float(os.environ.get("GOOD_TTL", "90"))


def build_model() -> dict:
    """The page model for one request, with a short memory.

    A failure to READ the Docker API is not a fact about the firewall, and must not
    be rendered as one. For the first GOOD_TTL seconds a failed rebuild serves the
    last good read with an explicit banner; after that the model is built DEGRADED,
    which reports "unknown" instead of inventing findings. Both exist because a
    one-second socket-proxy restart used to make this page (and the widget) say
    "guard down · 15 issues" while the guard was enforcing normally: the guard's
    chains are installed by its own process, not derived from this view.
    """
    try:
        model = _build_model(None)
    except DockerError as exc:
        log("docker read failed: %s" % exc)
        last = _LAST_GOOD["model"]
        last_at = float(_LAST_GOOD["at"] or 0.0)
        if last is not None and (time.time() - last_at) <= GOOD_TTL:
            served = dict(last)
            # Copy the list: `served` shares the stored model's objects, and
            # appending to it in place would poison the snapshot for the next read.
            served["warnings"] = list(last["warnings"]) + [
                {
                    "tone": "warn",
                    "kind": "api-blip",
                    "text": "the Docker API read failed at %s (<code>%s</code>) — showing "
                    "the last good read from %s. Membership is as of then; the guard "
                    "itself is unaffected, because its chains are installed by its own "
                    "process, not by this page."
                    % (
                        time.strftime("%H:%M:%S"),
                        esc(str(exc)),
                        time.strftime("%H:%M:%S", time.localtime(last_at)),
                    ),
                }
            ]
            served["read_error"] = str(exc)
            return served
        # Never store a degraded model as the "last good" one: doing that makes the
        # next blip serve a model that already admits it cannot see docker, with a
        # bogus "last good read at ..." banner stacked on top of it.
        return _build_model(str(exc))
    _LAST_GOOD["at"] = time.time()
    _LAST_GOOD["model"] = model
    return model


def _build_model(degraded_error: str | None) -> dict:
    conf = read_guard_conf()
    status = read_status()
    # Observe-mode evidence is published by the guard itself (it is the process with
    # CAP_SYSLOG), so this app needs no kernel-log access — which is what lets it run
    # as uid 1000 and own the config it writes.
    observed = (status or {}).get("observed") or {
        "ok": False,
        "error": "the guard is not publishing observed flows yet — restart it once",
        "boot_at": 0,
        "flows": [],
    }
    boot_at = float(observed.get("boot_at") or 0)
    shared = read_shared_defs()

    if degraded_error is not None:
        # Every docker fact is unknown this time. Raising out of the reads would
        # only be caught by build_model; doing it here keeps "degraded" explicit.
        networks: dict = {}
        containers: list = []
        docker_error: str | None = degraded_error
    else:
        networks = {n.get("Name"): n for n in docker_networks()}
        containers = docker_containers()
        docker_error = None

    # Networks that opt in with a label need no file at all: `docker network create
    # --label netguard.bus=true <name>` is enough for the UI to list it as unguarded.
    if docker_error is None:
        for nname, n in networks.items():
            labels = n.get("Labels") or {}
            if str(labels.get(BUS_LABEL, "")).lower() in ("true", "1", "yes"):
                ipam = ((n.get("IPAM") or {}).get("Config") or [{}])[0]
                entry = shared.setdefault(
                    nname,
                    {
                        "name": nname,
                        "subnet": ipam.get("Subnet", ""),
                        "ip_range": ipam.get("IPRange", ""),
                        "internal": bool(n.get("Internal")),
                        "sources": set(),
                    },
                )
                entry["sources"].add("label")

    policies = {p["name"]: p for p in conf["policies"]}
    order = list(shared.keys())
    for name in policies:
        if name not in order:
            order.append(name)
    bus_names = set(order)

    # Membership: bus -> list of member dicts.
    #
    # Aliases are only in the per-container inspect, NOT in /containers/json (the
    # summary returns `Aliases: null` for every endpoint — verified against the live
    # API), and /networks/{id} reports an empty Aliases list too. So membership is
    # cheap (one call) and aliases cost one inspect per container that is on a bus we
    # care about. Cached; a page load after the first is free.
    members: dict[str, list[dict]] = {}
    if docker_error:
        # Nothing to resolve against. An inspect here would raise again and there is
        # no partial answer worth keeping.
        guard_ct = None
        guard_inspect: dict = {}
        trafficjam = None
    else:
        for c in containers:
            nets = (c.get("NetworkSettings") or {}).get("Networks") or {}
            on_bus = bus_names & set(nets)
            if not on_bus:
                continue
            name = (c.get("Names") or ["?"])[0].lstrip("/")
            detail = docker_inspect(c.get("Id") or "")
            full_nets = ((detail or {}).get("NetworkSettings") or {}).get("Networks") or {}
            for netname in sorted(on_bus):
                endpoint = full_nets.get(netname) or nets.get(netname) or {}
                aliases = sorted(set(endpoint.get("Aliases") or []))
                members.setdefault(netname, []).append(
                    {
                        "name": name,
                        "write_as": write_as({"name": name, "aliases": aliases}),
                        "id": (c.get("Id") or "")[:12],
                        "ip": endpoint.get("IPAddress") or "",
                        "aliases": aliases,
                        "image": c.get("Image", ""),
                        "state": c.get("State", ""),
                    }
                )

        guard_ct = next(
            (c for c in containers if (c.get("Names") or [""])[0].lstrip("/") == GUARD_CONTAINER),
            None,
        )
        guard_inspect = docker_inspect(GUARD_CONTAINER) or {}
        trafficjam = docker_inspect("trafficjam")

    now = time.time()
    status_age = None
    if status and status.get("now"):
        status_age = max(0.0, now - float(status["now"]))

    # `None` means "could not ask", which is different from "it is not running".
    if docker_error:
        container_running = None
    else:
        container_running = bool(guard_ct and guard_ct.get("State") == "running")
    state = guard_state(status, status_age, container_running, docker_error)

    live = {}
    for p in (status or {}).get("policies", []):
        live[p.get("name")] = p

    buses = []
    for name in order:
        net = networks.get(name) or {}
        ipam = ((net.get("IPAM") or {}).get("Config") or [{}])[0]
        policy = policies.get(name)
        live_p = live.get(name)
        bus_members = sorted(members.get(name, []), key=lambda m: m["name"].lower())
        subnet = (policy or {}).get("subnet") or ipam.get("Subnet") or shared.get(name, {}).get("subnet", "")
        ip_range = ipam.get("IPRange") or shared.get(name, {}).get("ip_range", "")
        warn: list[dict] = []

        # ip -> container(s) on this bus. Literal allowlist entries are matched by
        # ADDRESS (the guard never resolves them), so a name is only ever a label
        # for the reader — which is why the raw entry stays available as a tooltip
        # and in the detail table's address column.
        by_ip: dict[str, list[str]] = {}
        for m in bus_members:
            if m["ip"]:
                by_ip.setdefault(m["ip"], []).append(m["name"])

        resolved = []
        if policy and docker_error:
            # No membership to resolve against. Claiming "matches no container" here
            # would be a false accusation about the policy — the guard resolves from
            # the host netns over the pinned proxy IP and is unaffected.
            resolved = [
                {
                    "entry": entry,
                    "target": split_entry(entry)[0],
                    "port": split_entry(entry)[1] or "*",
                    "ips": [],
                    "status": "unknown",
                    "names": [],
                }
                for entry in policy["entries"]
            ]
        elif policy:
            for entry in policy["entries"]:
                target, port = split_entry(entry)
                if is_ipv4(target) or target == "*":
                    resolved.append(
                        {
                            "entry": entry,
                            "target": target,
                            "port": port or "*",
                            "ips": [target],
                            "status": "literal",
                            "names": sorted(set(by_ip.get(target, []))),
                        }
                    )
                    if target != "*" and ip_range and ip_in_subnet(target, ip_range):
                        warn.append(
                            {
                                "tone": "warn",
                                "kind": "pin",
                                "text": "%s is a literal inside the busses dynamic IP range (%s) — IPAM can hand that address to another container."
                                % (target, ip_range),
                            }
                        )
                    continue
                hits = [
                    m
                    for m in bus_members
                    if target.lower() in [a.lower() for a in m["aliases"]]
                ]
                resolved.append(
                    {
                        "entry": entry,
                        "target": target,
                        "port": port or "*",
                        "ips": [m["ip"] for m in hits if m["ip"]],
                        "status": "resolved" if hits else "unresolved",
                        "names": sorted({m["name"] for m in hits}),
                    }
                )
                if not hits:
                    warn.append(
                        {
                            "tone": "bad",
                            "kind": "unresolved",
                            "text": "allowlist entry %r matches no container on this bus — the guard SKIPS it, and a policy whose whole allowlist is unresolved is refused (bus left unfiltered)."
                            % entry,
                        }
                    )
                elif len({m["ip"] for m in hits if m["ip"]}) > 1:
                    warn.append(
                        {
                            "tone": "warn",
                            "kind": "ambiguous",
                            "text": "%r is ambiguous: it resolves to %d addresses on this bus. One alias must name one service."
                            % (entry, len({m["ip"] for m in hits if m["ip"]})),
                        }
                    )

        current = None if docker_error else normalize([e for r in resolved for e in expand_entry(r)])

        if policy and ipam.get("Subnet") and policy["subnet"] != ipam.get("Subnet"):
            warn.append(
                {
                    "tone": "bad",
                    "kind": "subnet",
                    "text": "policy subnet %s does not match the live network subnet %s — the chain would match nothing."
                    % (policy["subnet"], ipam.get("Subnet")),
                }
            )

        if live_p:
            if live_p.get("state") == "refused":
                warn.append(
                    {
                        "tone": "bad",
                        "kind": "refused",
                        "text": "the guard refused to install this policy (allowlist resolved empty) — the bus is UNFILTERED until an entry resolves.",
                    }
                )
            elif not live_p.get("hooked"):
                warn.append(
                    {
                        "tone": "bad",
                        "kind": "unhooked",
                        "text": "chain %s is not hooked into DOCKER-USER right now — the policy is not being applied."
                        % ("DOCKERNET_" + name),
                    }
                )
            elif current and live_p.get("installed") != current:
                warn.append(
                    {
                        "tone": "warn",
                        "kind": "drift",
                        "text": "installed allowlist (%s) differs from what current membership resolves to (%s) — a recreate is pending, or the guard just detected drift and is about to rebuild."
                        % (live_p.get("installed") or "empty", current),
                    }
                )

        if not policy:
            warn.append(
                {
                    "tone": "bad",
                    "kind": "open",
                    "text": "no policy: every member can reach every other member on this bus.",
                }
            )

        # Where this bus came from. The three sources are a union, not a sync: the
        # guard only ever reads its config, while buses.txt and the label merely tell
        # this page that the network exists (so an unguarded one is visible at all).
        definition_sources = (shared.get(name) or {}).get("sources") or set()
        sources = (["policy"] if policy else []) + [
            s for s in ("file", "label") if s in definition_sources
        ]

        if not docker_error:
            if policy and not net:
                warn.append(
                    {
                        "tone": "bad",
                        "kind": "missing-net",
                        "text": "the policy names network %s, but docker has no network by "
                        "that name — the chain matches nothing. Fix the name, or remove "
                        "the policy." % name,
                    }
                )
            elif "file" in definition_sources and not net:
                warn.append(
                    {
                        "tone": "warn",
                        "kind": "stale-entry",
                        "text": "%s is listed in the bus definitions, but docker has no "
                        "network by that name — a stale entry, harmless but noise." % name,
                    }
                )

        buses.append(
            {
                "name": name,
                "subnet": subnet,
                "ip_range": ip_range,
                "internal": bool(net.get("Internal") or shared.get(name, {}).get("internal")),
                "exists": bool(net),
                "members": bus_members,
                "member_count": len(bus_members),
                "membership": "unknown" if docker_error else "ok",
                "sources": sources,
                "policy": policy,
                "mode": conf["modes"].get(name, "enforce") if policy else None,
                "resolved": resolved,
                "live": live_p,
                "warnings": warn,
                "drops": (
                    {
                        "ok": bool(observed.get("ok")),
                        "error": observed.get("error"),
                        "flows": sorted(
                            [
                                {
                                    "src": f.get("src"),
                                    "dst": f.get("dst"),
                                    "proto": f.get("proto"),
                                    "dpt": str(f.get("dport") or "0"),
                                    "count": int(f.get("count") or 0),
                                    "first_wall": wall_clock(boot_at, f.get("first")),
                                    "last_wall": wall_clock(boot_at, f.get("last")),
                                }
                                for f in (observed.get("flows") or [])
                                if f.get("bus") == name
                            ],
                            key=lambda f: (-f["count"], f["dst"] or ""),
                        ),
                    }
                    if policy
                    else None
                ),
            }
        )

    # ── global posture ────────────────────────────────────────────────────────
    global_warnings = []
    policied = {p["name"] for p in conf["policies"]}
    open_buses = [b["name"] for b in buses if not b["policy"]]

    if docker_error:
        global_warnings.append(
            {"tone": "bad", "kind": "docker", "text": "docker API unavailable: %s" % docker_error}
        )
    if not conf["ok"]:
        global_warnings.append(
            {"tone": "bad", "kind": "conf", "text": "cannot read the guard config: %s" % conf["error"]}
        )
    if status is None:
        global_warnings.append(
            {
                "tone": "warn",
                "kind": "no-status",
                "text": "the guard is not publishing status yet, so chain state is unavailable below (intent and membership are still live). A guard older than the revision that added status.json never writes one — restart it once.",
            }
        )
    else:
        if status_age is not None and status_age > 3 * float(status.get("poll_interval") or 60):
            global_warnings.append(
                {
                    "tone": "bad",
                    "kind": "stale",
                    "text": "status is %.0fs old (poll interval %ss) — the guard may be stopped or wedged. Its chains stay installed when it dies, so this is not automatically an open bus."
                    % (status_age, status.get("poll_interval")),
                }
            )
        if status.get("config", {}).get("md5") and status["config"]["md5"] != conf["md5"]:
            reload_err = (status.get("config") or {}).get("reload_error") or ""
            if reload_err:
                text = (
                    "the config on disk was <b>refused</b>, so the running policy is the "
                    "previous one: <code>%s</code>" % esc(reload_err)
                )
            else:
                text = (
                    "the config on disk differs from the one the guard is running — a "
                    "reload is pending (applied within one poll, no restart needed) or was "
                    "refused; the guard's own logs have the reason."
                )
            global_warnings.append({"tone": "warn", "kind": "reload", "text": text})

    if open_buses:
        global_warnings.append(
            {
                "tone": "bad",
                "kind": "open",
                "text": "%d bus(es) have no policy: %s."
                % (len(open_buses), ", ".join(sorted(open_buses))),
            }
        )

    known_chains = {"DOCKERNET_" + n for n in policied} | {"CROWDSEC_CHAIN"}
    strays = [t for t in (status or {}).get("docker_user", []) if t not in known_chains]
    if strays:
        global_warnings.append(
            {
                "tone": "warn",
                "kind": "stray-jump",
                "text": "DOCKER-USER still jumps to %s — a chain no policy in the config owns any more. It keeps enforcing whatever it holds; clear it deliberately, not by accident."
                % ", ".join(strays),
            }
        )
    if trafficjam and trafficjam.get("State", {}).get("Running"):
        global_warnings.append(
            {
                "tone": "warn",
                "kind": "trafficjam",
                "text": "the retired trafficjam container is RUNNING (%s) and enforces the proxy bus a second time, alongside DOCKERNET_proxy. Its `proxy` role moved into the guard on 2026-10-30; stop it and remove its compose service."
                % (trafficjam.get("State", {}).get("Status") or "up"),
            }
        )

    counts = {
        "buses": len(buses),
        "enforce": sum(1 for b in buses if b["mode"] == "enforce"),
        "observe": sum(1 for b in buses if b["mode"] == "observe"),
        "open": len(open_buses),
    }

    return {
        "version": VERSION,
        "rendered_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "buses": buses,
        "counts": counts,
        "warnings": global_warnings,
        "conf": {
            "ok": conf["ok"],
            "error": conf["error"],
            "md5": conf["md5"],
            # Needed by the editor to prefill the mode and by allow-flow to keep it.
            "modes": conf["modes"],
        },
        "guard": {
            "status": status,
            "status_age": status_age,
            "state": state,
            "running": container_running,
            "started_at": (guard_inspect.get("State") or {}).get("StartedAt"),
            "restart_count": guard_inspect.get("RestartCount"),
            "observed": {
                "ok": bool(observed.get("ok")),
                "error": observed.get("error"),
                "flows": len(observed.get("flows") or []),
            },
        },
        "docker": {"error": docker_error},
    }


# ─── rule editing (stage 2) ───────────────────────────────────────────────────
# Writes the SAME file the guard sources, and only that file. Three properties are
# deliberate and load-bearing:
#
#   * comments survive. The config is a document — every comment in it explains a
#     decision that cost somebody an afternoon. So the editor rewrites the POLICIES
#     block and the MODES line and nothing else; a regenerate-from-model would throw
#     all of it away.
#   * the written file is re-parsed before it is written, and the pre-write version
#     is backed up. A bad write is a firewall mistake; a refused parse is not.
#   * nothing is committed. The repo is the truth and a push deploys other stacks;
#     the editor applies live (the guard reloads on md5 change) and shows the diff.
RULES_DIR = os.path.dirname(GUARD_CONF) or "/etc/netguard/rules"
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/data/backups")
WRITE_ENABLED = os.environ.get("NETGUARD_WRITE", "0") == "1"
MAX_BACKUPS = 20


class RuleError(Exception):
    """A refused edit. Carries the message shown to the user."""


def _policy_lines(policies: list[dict]) -> list[str]:
    return [
        "%-17s %s %s %s" % (p["name"], p["dir"], p["subnet"], p["allow"])
        for p in policies
    ]


def format_conf_text(original: str, policies: list[dict], modes: dict) -> str:
    """Replace the POLICIES block and the MODES line in `original`; keep the rest."""
    m = re.search(r'(?m)^POLICIES="[ \t]*\n', original)
    if not m:
        raise RuleError("cannot find the POLICIES block in the config")
    close = re.search(r'(?m)^"[ \t]*\n', original[m.end():])
    if not close:
        raise RuleError("cannot find the closing quote of the POLICIES block")
    body_start = m.end()
    body_end = body_start + close.start()

    new_body = "".join(line + "\n" for line in _policy_lines(policies))
    text = original[:body_start] + new_body + original[body_end:]

    # Preserve the existing order and append new buses: sorting would rewrite a line
    # nobody edited, which shows up as churn in every diff.
    modes_value = ",".join(
        "%s:%s" % (name, modes[name]) for name in modes if modes[name] != "enforce"
    )
    replaced, count = re.subn(r'(?m)^MODES="[^"\n]*"', 'MODES="%s"' % modes_value, text, count=1)
    if count != 1:
        raise RuleError("cannot find the MODES line in the config")
    return replaced


def write_as(member: dict) -> str:
    """The name to write in the allowlist for a member.

    Prefer a purpose alias (`navidrome-music`, `abs-dl`) because that is what the
    repo's convention uses and what survives a container rename; fall back to the
    container name, which docker also lists in .Aliases. Never an address: the guard
    re-resolves aliases every poll, so a recreate cannot silently repoint the rule.
    """
    purpose = [a for a in member.get("aliases") or [] if a and a != member["name"]]
    return (sorted(purpose, key=len)[0] if purpose else member["name"])


def validate_rule(model: dict, bus_name: str, shape: str, allow: list, mode: str,
                  keep: list | None = None):
    """-> (normalized allow list, warnings). Raises RuleError on anything fatal."""
    bus = next((b for b in model["buses"] if b["name"] == bus_name), None)
    if bus is None:
        raise RuleError("unknown bus %r" % bus_name)
    if bus.get("membership") != "ok":
        raise RuleError(
            "membership for %s is unavailable right now (the Docker API read failed) — "
            "an allowlist cannot be checked, so nothing was written" % bus_name
        )
    if not bus.get("exists"):
        raise RuleError("network %s does not exist" % bus_name)
    if shape not in ("callers", "servers"):
        raise RuleError("pick a shape: callers or servers")
    if mode not in ("enforce", "observe"):
        raise RuleError("mode must be enforce or observe")
    if not isinstance(allow, list) or not allow:
        raise RuleError("pick at least one app")

    by_target = {}
    for m in bus["members"]:
        by_target.setdefault(write_as(m), m)

    out = []
    # Entries the picker cannot express (a literal address: db_backups' reserved
    # backup pin) are carried through unchanged rather than silently dropped.
    for raw in keep or []:
        target, port = split_entry(str(raw))
        if not is_ipv4(target):
            raise RuleError("%r is not an app on this bus and not a literal address" % raw)
        out.append(str(raw))
    for item in allow:
        if isinstance(item, str):
            item = {"target": item, "port": ""}
        target = str(item.get("target") or "").strip()
        port = str(item.get("port") or "").strip()
        member = by_target.get(target)
        if member is None and target:
            # Accept a container name too: it is a valid docker alias.
            member = next((m for m in bus["members"] if m["name"] == target), None)
        if member is None:
            raise RuleError("%r is not on %s — the guard would skip it and, if the "
                            "whole allowlist failed, refuse the policy" % (target, bus_name))
        entry = write_as(member)
        if port:
            if shape != "servers":
                raise RuleError(
                    "ports only apply to \"only these apps may be connected to\" — a "
                    "caller is allowed to any port by definition"
                )
            if not port.isdigit() or not (0 < int(port) < 65536):
                raise RuleError("%r is not a TCP port" % port)
            entry = "%s:%s" % (entry, port)
        if entry in out:
            continue
        out.append(entry)
    if not out:
        raise RuleError("pick at least one app")

    warnings = []
    named = len(out)
    members = max(1, bus["member_count"])
    if shape == "callers" and named / members >= 0.7:
        warnings.append(
            "%d of %d members may initiate — that is most of the bus, so the rule is "
            "close to decorative" % (named, members)
        )
    if shape == "servers" and named / members >= 0.7:
        warnings.append("%d of %d members are reachable — that is most of the bus" % (named, members))
    return out, warnings


def _backup(text: str) -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    path = os.path.join(BACKUP_DIR, "docker-net-guard.conf.%s.bak" % stamp)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    for old in sorted(os.listdir(BACKUP_DIR))[:-MAX_BACKUPS]:
        if old.startswith("docker-net-guard.conf."):
            try:
                os.unlink(os.path.join(BACKUP_DIR, old))
            except OSError:
                pass
    return path


def allow_flow(model: dict, bus_name: str, payload: dict) -> dict:
    """Add the endpoint of one OBSERVED flow to an existing rule.

    This is the observe -> enforce loop: the flow table already names the pairs the
    rule would cut, so allowing one should not require retyping it. Which end gets
    added depends on the bus's own direction — a `src` rule names initiators, a `dst`
    rule names destinations — and the address is mapped back to the member's alias so
    the entry survives a recreate.
    """
    bus = next((b for b in model["buses"] if b["name"] == bus_name), None)
    if bus is None:
        raise RuleError("unknown bus %r" % bus_name)
    p = bus["policy"]
    if not p:
        raise RuleError("%s has no rule yet — create one first" % bus_name)

    dst_ip = str(payload.get("dst") or "").strip()
    src_ip = str(payload.get("src") or "").strip()
    dport = str(payload.get("dport") or "").strip()
    direction = p["dir"]
    ip = src_ip if direction == "src" else dst_ip
    member = next((m for m in bus["members"] if m["ip"] == ip), None)
    if member is None:
        raise RuleError("no container currently sits at %s on this bus" % (ip or "?"))

    picks, keep = _split_current(p, bus["members"])
    target = member["write_as"]
    port = dport if (direction == "dst" and dport and dport not in ("0", "*")) else ""
    if not any(x["target"] == target and x["port"] == port for x in picks):
        picks.append({"target": target, "port": port})
    mode = model["conf"]["modes"].get(bus_name, "enforce")
    return write_rule(
        model,
        bus_name,
        "callers" if direction == "src" else "servers",
        picks,
        mode,
        payload.get("md5"),
        keep,
    )


def _commit(original: str, new_text: str) -> str:
    """Back up, replace atomically, and return the unified diff.

    The replace is a rename inside the bind-mounted directory, so the guard either
    sees the old file or the whole new one. It re-reads on md5 change, so a write is
    live within one poll without touching the container.
    """
    _backup(original)
    tmp = os.path.join(RULES_DIR, ".docker-net-guard.conf.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(new_text)
        fh.flush()
        os.fsync(fh.fileno())
    # Keep whatever mode the file already had: 0664 was a root-owned deployment's
    # choice, and a published image must not impose it.
    try:
        os.chmod(tmp, os.stat(GUARD_CONF).st_mode & 0o777)
    except OSError:
        pass
    os.replace(tmp, GUARD_CONF)   # atomic within the filesystem
    return "".join(
        difflib.unified_diff(
            original.splitlines(True),
            new_text.splitlines(True),
            fromfile="docker-net-guard.conf (before)",
            tofile="docker-net-guard.conf (after)",
            n=2,
        )
    )


def set_rule_mode(model: dict, bus_name: str, mode: str, expected_md5: str | None) -> dict:
    """Flip enforce/observe without touching the allowlist."""
    if not WRITE_ENABLED:
        raise RuleError("editing is disabled on this deployment (NETGUARD_WRITE=0)")
    if mode not in ("enforce", "observe"):
        raise RuleError("mode must be enforce or observe")
    with open(GUARD_CONF, "r", encoding="utf-8") as fh:
        original = fh.read()
    if expected_md5 and expected_md5 != hashlib.md5(original.encode()).hexdigest():
        raise RuleError("the config changed on disk since this page was loaded — reload first")
    parsed = parse_conf_text(original)
    if not parsed["ok"]:
        raise RuleError("the current config does not parse: %s" % parsed["error"])
    if not any(p["name"] == bus_name for p in parsed["policies"]):
        raise RuleError("%s has no policy to switch" % bus_name)
    modes = dict(parsed["modes"])
    if mode == "observe":
        modes[bus_name] = "observe"
    else:
        modes.pop(bus_name, None)
    new_text = format_conf_text(original, parsed["policies"], modes)
    diff = _commit(original, new_text)
    return {"message": "%s is now %s — applies within 60s" % (bus_name, mode), "diff": diff}


def write_rule(model: dict, bus_name: str, shape: str, allow: list, mode: str,
               expected_md5: str | None, keep: list | None = None) -> dict:
    """Validate, then rewrite the config atomically. Returns {message, diff}."""
    if not WRITE_ENABLED:
        raise RuleError("editing is disabled on this deployment (NETGUARD_WRITE=0)")

    entries, warnings = validate_rule(model, bus_name, shape, allow, mode, keep)

    with open(GUARD_CONF, "r", encoding="utf-8") as fh:
        original = fh.read()
    on_disk = hashlib.md5(original.encode()).hexdigest()
    if expected_md5 and expected_md5 != on_disk:
        raise RuleError(
            "the config changed on disk since this page was loaded — reload and redo the "
            "edit rather than overwriting somebody else's change"
        )

    parsed = parse_conf_text(original)
    if not parsed["ok"]:
        raise RuleError("the current config does not parse, refusing to edit it: %s" % parsed["error"])

    bus = next(b for b in model["buses"] if b["name"] == bus_name)
    subnet = bus.get("subnet") or ""
    if not subnet:
        raise RuleError("cannot determine the subnet of %s" % bus_name)

    policies = [dict(p) for p in parsed["policies"]]
    modes = dict(parsed["modes"])
    direction = "src" if shape == "callers" else "dst"
    entry = {
        "name": bus_name,
        "dir": direction,
        "subnet": subnet,
        "allow": ",".join(entries),
        "entries": entries,
    }
    for i, p in enumerate(policies):
        if p["name"] == bus_name:
            policies[i] = entry
            break
    else:
        policies.append(entry)
    if mode == "observe":
        modes[bus_name] = "observe"
    else:
        modes.pop(bus_name, None)

    new_text = format_conf_text(original, policies, modes)
    check = parse_conf_text(new_text)
    if not check["ok"]:
        raise RuleError("refusing to write a config that does not re-parse: %s" % check["error"])
    if not any(p["name"] == bus_name and p["allow"] == ",".join(entries) for p in check["policies"]):
        raise RuleError("the rendered policy did not survive a re-parse; nothing written")

    diff = _commit(original, new_text)
    message = "saved — the guard reloads within 60s"
    if warnings:
        message += "; " + "; ".join(warnings)
    return {"message": message, "diff": diff}


def delete_rule(model: dict, bus_name: str, expected_md5: str | None) -> dict:
    if not WRITE_ENABLED:
        raise RuleError("editing is disabled on this deployment (NETGUARD_WRITE=0)")
    with open(GUARD_CONF, "r", encoding="utf-8") as fh:
        original = fh.read()
    if expected_md5 and expected_md5 != hashlib.md5(original.encode()).hexdigest():
        raise RuleError("the config changed on disk since this page was loaded — reload first")
    parsed = parse_conf_text(original)
    if not parsed["ok"]:
        raise RuleError("the current config does not parse: %s" % parsed["error"])
    policies = [p for p in parsed["policies"] if p["name"] != bus_name]
    if len(policies) == len(parsed["policies"]):
        raise RuleError("%s has no policy to remove" % bus_name)
    modes = {k: v for k, v in parsed["modes"].items() if k != bus_name}
    new_text = format_conf_text(original, policies, modes)
    diff = _commit(original, new_text)
    return {
        "message": "removed — %s is OPEN from the next guard poll; its chain is cleared on reload" % bus_name,
        "diff": diff,
    }


# ─── homepage widget ──────────────────────────────────────────────────────────
def wall_clock(boot_at: float, seconds) -> str:
    """Kernel seconds-since-boot -> local HH:MM:SS, using the guard's boot_at."""
    try:
        ts = float(seconds)
    except (TypeError, ValueError):
        return "—"
    if boot_at and ts:
        return time.strftime("%H:%M:%S", time.localtime(boot_at + ts))
    return "+%.0fs" % ts


def fmt_age(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 90:
        return "%ds" % seconds
    if seconds < 5400:
        return "%dm" % (seconds // 60)
    return "%dh%02d" % (seconds // 3600, (seconds % 3600) // 60)


def build_widget() -> dict:
    """Compact, FLAT JSON for homepage's `customapi` widget.

    Flat on purpose: homepage maps a widget row per key, and keeping the shape
    trivial means the dashboard never breaks because a nested path or an absent
    field changed shape. It is served on the `homepage_widgets` bus only (the
    container publishes no port), where the guard's policy lets homepage and
    nothing else initiate — so it needs no auth of its own, exactly like the other
    `-widget` endpoints here.

    Nothing sensitive: counts and states, no addresses, names or flows.
    """
    m = build_model()
    g = m["guard"]
    c = m["counts"]
    age = g["status_age"]
    state = g.get("state") or "unknown"
    if state in ("up", "stale") and age is not None:
        guard = "%s %s" % (state, fmt_age(age))
    else:
        guard = state    # down / unknown / no status

    # Real POLICY problems only. Two kinds are excluded on purpose:
    #   * open — most buses here are deliberately unguarded, so counting them would
    #     leave the widget permanently red and therefore unreadable;
    #   * api-blip — a read failure that a fresh snapshot covered. It is a fact about
    #     this container's view, not about the firewall, and the page banner already
    #     says so. A SUSTAINED outage does count, via the "docker" warning.
    ignore = {"open", "api-blip"}
    issues = sum(
        1 for b in m["buses"] for w in b["warnings"] if w.get("kind") not in ignore
    ) + sum(1 for w in m["warnings"] if w.get("kind") not in ignore)

    flows = sum(
        len(b["drops"]["flows"])
        for b in m["buses"]
        if b.get("drops") and b["drops"].get("ok")
    )
    xb = (g["status"] or {}).get("xbridge") or {}

    return {
        "guard": guard,
        "buses": "%d enforce · %d observe · %d open" % (c["enforce"], c["observe"], c["open"]),
        "issues": issues,
        "drops": "%d flows" % flows,
        "xbridge": "%s bridges · %s rules" % (xb.get("bridges") or 0, xb.get("rules") or 0),
        "updated": m["rendered_at"],
    }


# ─── rendering ────────────────────────────────────────────────────────────────
CSS = """
:root{
  --bg:#fbfaf8; --fg:#1c1b19; --mut:#6b6862; --line:#e3e0da;
  --card:#ffffff; --chip:#f0eee9; --ok:#1a7f4b; --warn:#a86a00; --bad:#b3261e;
  --accent:#2f5d8a; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#16181a; --fg:#e8e6e3; --mut:#9b978f; --line:#2c2f33;
    --card:#1d2023; --chip:#25292d; --ok:#5cc98d; --warn:#e0a33a; --bad:#f2776d;
    --accent:#7fb0dd;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:15px;line-height:1.45;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:22px 18px 60px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
h1{font-size:1.3rem;margin:0;letter-spacing:-.01em}
h2{font-size:.98rem;margin:26px 0 8px;letter-spacing:.01em}
.sub{color:var(--mut);font-size:.82rem;margin-top:3px}
.top{display:flex;flex-wrap:wrap;gap:12px;justify-content:space-between;align-items:flex-end}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{background:var(--chip);color:var(--mut);border-radius:99px;padding:2px 9px;font-size:.74rem;white-space:nowrap}
.chip b{color:var(--fg);font-weight:600}
.badge{display:inline-block;border-radius:5px;padding:1px 7px;font-size:.73rem;font-weight:600;
  border:1px solid transparent;white-space:nowrap}
.badge.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent);background:color-mix(in srgb,var(--ok) 10%,transparent)}
.badge.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 35%,transparent);background:color-mix(in srgb,var(--warn) 10%,transparent)}
.badge.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 38%,transparent);background:color-mix(in srgb,var(--bad) 10%,transparent)}
.badge.mut{color:var(--mut);border-color:var(--line);background:var(--chip)}
.warns{margin:16px 0 4px;display:flex;flex-direction:column;gap:6px}
.warn-item{display:flex;gap:9px;font-size:.84rem;padding:8px 11px;border-radius:7px;
  background:color-mix(in srgb,var(--warn) 8%,var(--card));border:1px solid color-mix(in srgb,var(--warn) 22%,var(--line))}
.warn-item.bad{background:color-mix(in srgb,var(--bad) 8%,var(--card));border-color:color-mix(in srgb,var(--bad) 24%,var(--line))}
.dot{width:7px;height:7px;border-radius:99px;margin-top:7px;flex:0 0 auto;background:var(--warn)}
.warn-item.bad .dot{background:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:.85rem;background:var(--card);
  border:1px solid var(--line);border-radius:9px;overflow:hidden}
th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
  font-weight:600;padding:9px 11px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--chip) 55%,transparent)}
td{padding:9px 11px;border-bottom:1px solid color-mix(in srgb,var(--line) 65%,transparent);vertical-align:top}
tr:last-child td{border-bottom:0}
tr:hover td{background:color-mix(in srgb,var(--chip) 30%,transparent)}
.mono{font-family:var(--mono);font-size:.8rem}
.mut{color:var(--mut)}
.num{text-align:right;font-variant-numeric:tabular-nums;color:var(--mut)}
.scroll{overflow-x:auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:14px 16px;margin-top:14px}
.card h3{margin:0 0 4px;font-size:1.02rem}
.plain{font-size:.9rem;margin:6px 0 0}
.split{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:14px}
.kv{font-size:.84rem}
.kv div{display:flex;justify-content:space-between;gap:12px;padding:3px 0;border-bottom:1px dashed color-mix(in srgb,var(--line) 70%,transparent)}
.kv div:last-child{border-bottom:0}
.kv span:first-child{color:var(--mut)}
.note{font-size:.78rem;color:var(--mut);margin-top:10px}
footer{margin-top:34px;font-size:.75rem;color:var(--mut)}
/* rule editor */
.lbl{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:600;margin:18px 0 6px}
.opt{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:9px;padding:10px 12px;background:var(--card);cursor:pointer;margin-bottom:6px}
.opt input{margin:3px 0 0}
.opt b{font-weight:600;font-size:.9rem}
.opt em{display:block;color:var(--mut);font-size:.8rem;font-style:normal;margin-top:2px}
.picker{border:1px solid var(--line);border-radius:9px;background:var(--card);overflow:hidden;max-height:420px;overflow-y:auto}
.prow{display:flex;align-items:center;gap:10px;padding:6px 10px;border-bottom:1px solid color-mix(in srgb,var(--line) 60%,transparent)}
.prow:last-child{border-bottom:0}
.prow label{flex:1;display:flex;gap:8px;align-items:center;cursor:pointer;font-size:.85rem}
.prow input[type=checkbox]{margin:0}
.port{width:6.5rem;border:1px solid var(--line);border-radius:6px;background:color-mix(in srgb,var(--chip) 40%,transparent);padding:2px 6px;font-family:var(--mono);font-size:.78rem;color:var(--fg)}
.btn{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:7px;padding:6px 14px;font-size:.85rem;font-weight:600;cursor:pointer;font-family:inherit;text-decoration:none;display:inline-block}
.btn.pri{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,var(--line))}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px;align-items:center}
.prevbox{border:1px solid color-mix(in srgb,var(--ok) 30%,var(--line));background:color-mix(in srgb,var(--ok) 7%,var(--card));border-radius:8px;padding:10px 12px;font-size:.84rem;margin-top:6px}
.diff{font-family:var(--mono);font-size:.76rem;white-space:pre-wrap;background:var(--chip);border-radius:7px;padding:10px;overflow-x:auto;margin-top:8px}
.saved{border:1px solid color-mix(in srgb,var(--ok) 35%,var(--line));background:color-mix(in srgb,var(--ok) 8%,var(--card));border-radius:9px;padding:10px 12px;font-size:.85rem;margin-bottom:14px}
code{font-family:var(--mono);font-size:.85em;background:var(--chip);padding:1px 5px;border-radius:4px}
"""


def badge(text: str, tone: str) -> str:
    return '<span class="badge %s">%s</span>' % (tone, esc(text))


def posture_badge(bus: dict) -> str:
    if not bus["policy"]:
        return badge("open", "bad")
    return badge(bus["mode"], "ok" if bus["mode"] == "enforce" else "warn")


def entry_label(resolved: dict) -> tuple[str, str]:
    """(label, raw) for one allowlist entry — the app name where we can resolve it.

    A literal entry is matched by the guard by ADDRESS, so the name is a reading aid,
    not the policy: `raw` is the config text and is rendered as the tooltip. `None`
    names (a reserved pin, e.g. db_backups' future backup container) fall back to the
    address itself, which is the honest answer there — there is no app yet.
    """
    port = "" if resolved["port"] in (None, "*") else ":" + resolved["port"]
    if resolved["status"] == "literal" and resolved["names"]:
        return resolved["names"][0] + port, resolved["entry"]
    return resolved["entry"], ""


def restriction_summary(bus: dict) -> str:
    p = bus["policy"]
    if not p:
        return '<span class="mut">—</span>'
    labels = [entry_label(r)[0] for r in bus["resolved"]]
    text = ", ".join(labels)
    if len(text) > 46:
        text = text[:44] + "…"
    # Hover shows the config text (addresses), so a name never hides which address
    # the rule actually matches.
    title = ' title="config: %s"' % esc(", ".join(p["entries"]))
    if p["dir"] == "src":
        head = 'src · only <span class="mono"%s>%s</span> initiates' % (title, esc(text))
    else:
        head = 'dst · reaches only <span class="mono"%s>%s</span>' % (title, esc(text))
    return head


def plain_english(bus: dict) -> str:
    p = bus["policy"]
    verb = "dropped" if bus["mode"] == "enforce" else "logged and still allowed"
    codes = []
    for r in bus["resolved"]:
        label, raw = entry_label(r)
        title = ' title="config: %s"' % esc(raw) if raw else ""
        codes.append("<code%s>%s</code>" % (title, esc(label)))
    entries = ", ".join(codes)
    if p["dir"] == "src":
        return (
            "Only %s may <b>initiate</b> traffic on this bus. Every other "
            "member&rarr;member flow is %s." % (entries, verb)
        )
    return (
        "Any member may reach <b>only</b> %s. Every other member&rarr;member "
        "flow is %s." % (entries, verb)
    )


def render_page(title: str, body: str, model: dict | None = None) -> str:
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        "<title>%s</title><style>%s</style></head><body><div class=wrap>%s</div></body></html>"
        % (esc(title), CSS, body)
    )


def render_header(model: dict, subtitle: dict) -> str:
    g = model["guard"]
    c = model["counts"]
    st = g["status"]
    guard_chip = '<span class="chip">guard <b>%s</b></span>' % esc(g.get("state") or "unknown")
    if st:
        guard_chip += '<span class="chip">poll <b>%ss</b></span>' % esc(st.get("poll_interval"))
        if g["status_age"] is not None:
            guard_chip += '<span class="chip">status <b>%ss ago</b></span>' % round(g["status_age"])
    if g.get("restart_count") is not None:
        guard_chip += '<span class="chip">restarts <b>%s</b></span>' % esc(g["restart_count"])
    if st and st.get("xbridge"):
        xb = st["xbridge"]
        guard_chip += '<span class="chip">xbridge <b>%s bridges / %s rules</b></span>' % (
            esc(xb.get("bridges")),
            esc(xb.get("rules")),
        )
    return (
        "<div class=top><div><h1>%s</h1><div class=sub>%s</div></div>"
        '<div class=chips>%s<span class="chip">%d buses · <b>%d</b> enforce · '
        "<b>%d</b> observe · <b>%d</b> open</span></div></div>"
        % (
            esc(subtitle.get("title", "net-guard")),
            subtitle.get("sub", ""),
            guard_chip,
            c["buses"],
            c["enforce"],
            c["observe"],
            c["open"],
        )
    )


def render_warnings(items: list[dict]) -> str:
    if not items:
        return ""
    rows = "".join(
        '<div class="warn-item %s"><span class=dot></span><div>%s</div></div>'
        % ("bad" if w["tone"] == "bad" else "", w["text"])
        for w in items
    )
    return '<div class=warns>%s</div>' % rows


def render_list(model: dict) -> str:
    rows = []
    for bus in sorted(
        model["buses"],
        key=lambda b: (
            {"enforce": 0, "observe": 1}.get(b["mode"], 2),
            b["name"],
        ),
    ):
        live = bus["live"]
        if bus["policy"] and live:
            live_cell = "%s <span class=mut>· %s rules</span>" % (
                badge("installed", "ok") if live.get("hooked") and live.get("state") == "ok"
                else badge(live.get("state") or "?", "bad" if live.get("state") == "refused" else "warn"),
                esc(live.get("rules")),
            )
        elif bus["policy"]:
            live_cell = '<span class="mut">no status</span>'
        else:
            live_cell = '<span class="mut">—</span>'
        flags = ""
        # An open bus is already named in the banner; repeating it as a per-row
        # "1 issue" is noise that trains you to ignore the column.
        issues = [w for w in bus["warnings"] if w.get("kind") != "open"]
        bad = [w for w in issues if w["tone"] == "bad"]
        warn = [w for w in issues if w["tone"] != "bad"]
        if bad:
            flags += badge("%d issue%s" % (len(bad), "" if len(bad) == 1 else "s"), "bad")
        elif warn:
            flags += badge("%d note%s" % (len(warn), "" if len(warn) == 1 else "s"), "warn")
        drops = bus.get("drops") or {}
        drop_cell = ""
        if drops.get("ok") and drops.get("flows"):
            drop_cell = '<span class=mut>%d flow(s)</span>' % len(drops["flows"])
        rows.append(
            "<tr><td><a class=mono href=\"/bus/%s\">%s</a>%s</td>"
            "<td class=mono>%s</td><td class=num>%s</td><td>%s</td>"
            "<td>%s</td><td>%s %s</td></tr>"
            % (
                urllib.parse.quote(bus["name"]),
                esc(bus["name"]),
                " " + badge("internal", "mut") if bus["internal"] else "",
                esc(bus["subnet"] or "—"),
                str(bus["member_count"]) if bus.get("membership") == "ok" else "—",
                restriction_summary(bus),
                posture_badge(bus),
                live_cell,
                flags or drop_cell,
            )
        )

    body = render_header(
        model,
        {
            "title": "net-guard",
            "sub": "East-west firewall policy for every shared docker bus — intent "
            "(config), loaded state (guard status) and membership (docker), side by side.",
        },
    )
    body += render_warnings(model["warnings"])
    body += (
        "<h2>Shared buses</h2><div class=scroll><table><thead><tr>"
        "<th>bus</th><th>subnet</th><th class=num>members</th><th>restriction</th>"
        "<th>mode</th><th>chain</th></tr></thead><tbody>%s</tbody></table></div>"
    ) % "".join(rows)
    body += (
        '<div class=note>Rendered %s. "mode" and allowlists are read from '
        "<code>docker-net-guard.conf</code>; the chain column comes from the guard's "
        "own status.json, so it reflects what is installed, not what was intended.</div>"
    ) % esc(model["rendered_at"])
    body += (
        '<footer><a href="/api/state">/api/state</a> · netguard v%s · %s · '
        "config <span class=mono>%s</span></footer>"
        % (
            esc(model.get("version") or VERSION),
            "editing enabled" if WRITE_ENABLED else "read-only",
            esc(model["conf"]["md5"][:12]),
        )
    )
    return render_page("net-guard", body)


def render_detail(model: dict, bus: dict, saved: bool = False) -> str:
    p = bus["policy"]
    live = bus["live"]

    body = render_header(
        model,
        {
            "title": bus["name"],
            "sub": '<a href="/">&larr; all buses</a> · %s%s · listed by %s'
            % (esc(bus["subnet"] or "not present"),
               " · internal" if bus["internal"] else "",
               esc(" + ".join(bus.get("sources") or ["—"]))),
        },
    )

    if saved:
        edit = read_last_edit(bus["name"])
        if edit:
            body += '<div class="saved"><b>%s</b><div class="note">%s</div>' % (
                esc(edit.get("message") or "saved"),
                "The file in the repo now differs from HEAD — commit it so the change survives.",
            )
            if edit.get("diff"):
                body += '<div class="diff">%s</div>' % esc(edit["diff"])
            body += "</div>"

    if WRITE_ENABLED:
        buttons = '<a class="btn%s" href="/bus/%s/edit">%s</a>' % (
            "" if p else " pri",
            urllib.parse.quote(bus["name"]),
            "Edit rule" if p else "&#43; Add rule",
        )
        if p:
            other = "observe" if bus["mode"] == "enforce" else "enforce"
            buttons += (
                ' <button class="btn" data-set-mode data-bus="%s" data-mode="%s">'
                "Set to %s</button>"
                % (esc(bus["name"]), other, other)
            )
        body += '<div class="actions" style="margin:0 0 14px">%s</div>' % buttons

    if p:
        body += "<div class=card><h3>%s %s</h3><div class=plain>%s</div>" % (
            posture_badge(bus),
            badge("ip-range " + (bus["ip_range"] or "?"), "mut"),
            plain_english(bus),
        )
        if bus["drops"] and bus["drops"].get("flows"):
            first = bus["drops"]["flows"][0]
            body += (
                "<div class=note>Observed would-be-drops: <b>%d</b> distinct flow(s), "
                "most frequent <code>%s &rarr; %s:%s</code> (%d packet%s). An "
                "<i>established</i> flow rides the conntrack RETURN and is never "
                "logged, so a quiet bus can still be carrying traffic.</div>"
                % (
                    len(bus["drops"]["flows"]),
                    esc(first["src"]),
                    esc(first["dst"]),
                    esc(first["dpt"]),
                    first["count"],
                    "" if first["count"] == 1 else "s",
                )
            )
        body += "</div>"
    else:
        body += (
            "<div class=card><h3>%s no policy</h3><div class=plain>"
            "Nothing in <code>docker-net-guard.conf</code> covers this bus, so the "
            "guard does not touch it: every member can open a flow to every other "
            "member (and to every port they listen on). The cross-bridge chain still "
            "applies — traffic from a <i>different</i> bridge is dropped.</div></div>"
            % badge("open", "bad")
        )

    body += render_warnings([w for w in bus["warnings"] if w.get("kind") != "open"])

    # allowlist
    if p:
        rows = []
        for r in bus["resolved"]:
            tone = {"resolved": "ok", "literal": "mut", "unresolved": "bad", "unknown": "mut"}[r["status"]]
            res_label = {
                "resolved": "by alias",
                "literal": "by address",
                "unresolved": "unresolved",
                "unknown": "unknown",
            }[r["status"]]
            label, raw = entry_label(r)
            entry_cell = "<span class=mono%s>%s</span>" % (
                ' title="config: %s"' % esc(raw) if raw else "",
                esc(label),
            )
            if r["names"]:
                who = esc(", ".join(r["names"]))
            elif r["status"] == "unknown":
                who = '<span class=mut>membership unknown — the Docker API read failed</span>'
            elif r["status"] == "literal":
                who = '<span class=mut>no container at this address (reserved pin)</span>'
            else:
                who = '<span class=bad>nothing on this bus</span>'
            rows.append(
                "<tr><td>%s</td><td>%s</td><td class=mono>%s</td><td>%s</td></tr>"
                % (entry_cell, badge(res_label, tone), esc(", ".join(r["ips"]) or "—"), who)
            )
        body += (
            "<h2>Allowlist</h2><div class=scroll><table><thead><tr>"
            "<th>entry</th><th>resolution</th><th>address</th><th>container</th>"
            "</tr></thead><tbody>%s</tbody></table></div>" % "".join(rows)
        )
        body += (
            '<div class=note>The guard re-resolves every alias on every poll, so this '
            "is also the drift check: an address that changes here changes in the "
            "chain within one poll.</div>"
        )

    # live state
    kv = []
    if live:
        kv.append(("chain", esc("DOCKERNET_" + bus["name"])))
        kv.append(("hooked in DOCKER-USER", badge("yes", "ok") if live.get("hooked") else badge("no", "bad")))
        kv.append(("rules installed", esc(live.get("rules"))))
        kv.append(("guard state", badge(live.get("state") or "?", "ok" if live.get("state") == "ok" else "bad")))
        kv.append(("resolved by guard", '<span class="mono">%s</span>' % esc(live.get("installed") or "empty")))
        kv.append(("mode", badge(live.get("mode") or "?", "ok" if live.get("mode") == "enforce" else "warn")))
    else:
        kv.append(
            (
                "chain",
                '<span class="mut">not reported — the guard has not published status yet '
                "(it publishes from the revision that added status.json; restart it once)</span>",
            )
        )
    body += (
        "<h2>Live state</h2><div class=card><div class=kv>%s</div></div>"
        % "".join("<div><span>%s</span><span>%s</span></div>" % (k, v) for k, v in kv)
    )

    # members
    allowed_names = {n for r in bus["resolved"] for n in r["names"]}
    role_label = (
        "allowed initiator"
        if p and p["dir"] == "src"
        else ("allowed destination" if p else "")
    )
    rows = []
    for m in bus["members"]:
        role = ""
        if p:
            role = (
                badge(role_label, "ok")
                if m["name"] in allowed_names
                else badge("restricted", "mut")
            )
        pinned = ""
        if bus["ip_range"] and m["ip"] and not ip_in_subnet(m["ip"], bus["ip_range"]):
            pinned = " " + badge("pinned", "mut")
        rows.append(
            "<tr><td class=mono>%s%s</td><td class=mono>%s</td><td class=mono mut>%s</td><td>%s</td></tr>"
            % (esc(m["name"]), pinned, esc(m["ip"] or "—"),
               esc(" ".join(a for a in m["aliases"] if a != m["name"]) or "—"), role)
        )
    if bus.get("membership") == "ok":
        members_head = "Members (%d)" % bus["member_count"]
        members_body = "".join(rows) or "<tr><td colspan=4 class=mut>none running</td></tr>"
    else:
        members_head = "Members (unknown)"
        members_body = (
            '<tr><td colspan=4 class=mut>membership unavailable — the Docker API read '
            "failed. This is a fact about netguard's view, not about the firewall: the "
            "guard installs its rules itself.</td></tr>"
        )
    body += (
        "<h2>%s</h2><div class=scroll><table><thead><tr>"
        "<th>container</th><th>address</th><th>aliases</th><th>role</th>"
        "</tr></thead><tbody>%s</tbody></table></div>" % (members_head, members_body)
    )

    # observed drops
    d = bus["drops"]
    if p and d is not None:
        if not d["ok"]:
            body += (
                "<h2>Observed would-be-drops</h2><div class=card><div class=plain>"
                "Unavailable: <code>%s</code>. This container needs <code>CAP_SYSLOG</code> "
                "and the host sets <code>kernel.dmesg_restrict=1</code>.</div></div>"
                % esc(d["error"])
            )
        elif not d["flows"]:
            body += (
                "<h2>Observed would-be-drops</h2><div class=card><div class=plain>"
                "No would-be-dropped flow in the kernel ring buffer right now. In "
                "<b>enforce</b> mode nothing is logged at all, so this is expected; "
                "in <b>observe</b> mode it means no new flow has matched the terminal "
                "rule since the buffer was last wrapped or the guard last restarted."
                "</div></div>"
            )
        else:
            rows = "".join(
                "<tr><td class=mono>%s</td><td class=mono>%s:%s</td><td class=mut>%s</td>"
                "<td class=num>%d</td><td class=mut>%s</td>"
                "<td>%s</td></tr>"
                % (
                    esc(f["src"]),
                    esc(f["dst"]),
                    esc(f["dpt"]),
                    esc(f["proto"]),
                    f["count"],
                    esc(f["last_wall"]),
                    (
                        '<button class="btn" style="padding:1px 8px;font-size:.74rem" '
                        'data-allow-flow data-bus="%s" data-src="%s" data-dst="%s" '
                        'data-dport="%s">allow</button>'
                        % (esc(bus["name"]), esc(f["src"]), esc(f["dst"]), esc(f["dpt"]))
                    )
                    if WRITE_ENABLED
                    else "",
                )
                for f in d["flows"]
            )
            body += (
                "<h2>Observed would-be-drops (%d flows)</h2><div class=scroll>"
                "<table><thead><tr><th>source</th><th>destination</th><th>proto</th>"
                "<th class=num>packets</th><th>last seen</th><th></th></tr></thead><tbody>%s"
                "</tbody></table></div>" % (len(d["flows"]), rows)
            )
            body += (
                '<div class=note>Read from the kernel ring buffer, which wraps and has '
                "no retention: this is a snapshot, not a history. These are the flows "
                "that would be dropped if the bus were switched to enforce — the point "
                "of observe mode.</div>"
            )

    if WRITE_ENABLED:
        body += (
            '<script type="application/json" id="ng-page">%s</script>'
            '<script src="/app.js"></script>'
            % json.dumps({"md5": model["conf"]["md5"], "bus": bus["name"]}).replace("</", "<\\/")
        )

    body += (
        "<footer>Allowlist and membership are live; chain facts come from the guard's "
        "status.json (%s).</footer>"
        % esc("poll %ss" % ((model["guard"]["status"] or {}).get("poll_interval") or "?"))
    )
    return render_page("%s · net-guard" % bus["name"], body)


# The editor's behaviour lives in one small script, served as a static asset so the
# page keeps a strict CSP (`script-src 'self'`, no inline script, no eval).
APP_JS = r"""
(function () {
  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(function (r) { return r.json(); });
  }
  function page() {
    var el = document.getElementById('ng-page');
    return el ? JSON.parse(el.textContent) : {md5: null};
  }

  // ── bus page: enforce/observe toggle, and "allow this flow" ─────────────
  Array.prototype.forEach.call(document.querySelectorAll('[data-set-mode]'), function (btn) {
    btn.addEventListener('click', function () {
      var bus = btn.dataset.bus, mode = btn.dataset.mode;
      if (mode === 'enforce' && !confirm(
          'Switch ' + bus + ' to enforce?\n\nFrom the next guard poll any flow that is ' +
          'not in the allowlist is DROPPED (it will hang, not refuse).')) return;
      btn.disabled = true;
      post('/api/rules/' + encodeURIComponent(bus) + '/mode',
           {mode: mode, md5: page().md5}).then(function (j) {
        if (j.ok) location.reload();
        else { alert(j.error || 'refused'); btn.disabled = false; }
      }).catch(function (e) { alert(String(e)); btn.disabled = false; });
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll('[data-allow-flow]'), function (btn) {
    btn.addEventListener('click', function () {
      btn.disabled = true;
      post('/api/rules/' + encodeURIComponent(btn.dataset.bus) + '/allow-flow', {
        src: btn.dataset.src, dst: btn.dataset.dst,
        dport: btn.dataset.dport, md5: page().md5
      }).then(function (j) {
        if (j.ok) location.href = j.redirect;
        else { alert(j.error || 'refused'); btn.disabled = false; }
      }).catch(function (e) { alert(String(e)); btn.disabled = false; });
    });
  });

  // ── rule editor ─────────────────────────────────────────────────────────
  var data = document.getElementById('ng-data');
  if (!data) return;
  var D = JSON.parse(data.textContent);
  var rows = Array.prototype.slice.call(document.querySelectorAll('.prow'));
  var save = document.getElementById('save');
  var err = document.getElementById('err');
  var preview = document.getElementById('preview');

  function shape() {
    var e = document.querySelector('input[name=shape]:checked');
    return e ? e.value : 'servers';
  }
  function mode() {
    var e = document.querySelector('input[name=mode]:checked');
    return e ? e.value : 'observe';
  }
  function selected() {
    return rows.filter(function (r) {
      return r.querySelector('input[type=checkbox]').checked;
    }).map(function (r) {
      return {target: r.dataset.target, port: (r.querySelector('.port').value || '').trim()};
    });
  }
  function showErr(msg) {
    if (!msg) { err.style.display = 'none'; return; }
    err.textContent = msg;
    err.style.display = '';
  }

  function render() {
    var ports = shape() === 'servers';
    rows.forEach(function (r) {
      var p = r.querySelector('.port');
      p.disabled = !ports;
      p.style.opacity = ports ? '1' : '.4';
    });
    var n = D.members;
    var sel = selected();
    var allowed = ports ? n * sel.length : sel.length * (n - 1);
    var total = n * (n - 1);
    var labels = sel.map(function (s) { return s.target + (s.port ? ':' + s.port : ''); });
    var text;
    if (!sel.length && !D.keep.length) {
      text = 'Pick at least one app above.';
    } else if (ports) {
      text = 'Any of the ' + n + ' members may connect to <b>' + labels.join(', ') +
             '</b>. Everything else on this bus is ' +
             (mode() === 'enforce' ? '<b>dropped</b>' : 'logged and allowed') + '.';
    } else {
      text = '<b>' + labels.join(', ') + '</b> may start connections and reach all ' + n +
             ' members. The other ' + Math.max(0, n - 1) + ' members may start nothing.';
    }
    text += ' <span class="mut">(~' + allowed + ' of ' + total + ' member&rarr;member pairs allowed)</span>';
    preview.innerHTML = text;
    save.disabled = !sel.length && !D.keep.length;
  }

  Array.prototype.forEach.call(document.querySelectorAll('input[name=shape], input[name=mode]'), function (i) {
    i.addEventListener('change', render);
  });
  rows.forEach(function (r) {
    r.querySelector('input[type=checkbox]').addEventListener('change', render);
    r.querySelector('.port').addEventListener('input', render);
  });

  save.addEventListener('click', function () {
    save.disabled = true;
    showErr('');
    post('/api/rules', {
      bus: D.bus, shape: shape(), mode: mode(),
      allow: selected(), keep: D.keep, md5: D.md5
    }).then(function (j) {
      if (j.ok) { location.href = j.redirect; }
      else { showErr(j.error || 'refused'); save.disabled = false; }
    }).catch(function (e) { showErr(String(e)); save.disabled = false; });
  });

  var rm = document.getElementById('remove');
  if (rm) {
    rm.addEventListener('click', function () {
      if (!confirm('Remove the rule for ' + D.bus + '?\n\nThat leaves the bus OPEN: every ' +
                   'member will be able to reach every other member on it.')) return;
      rm.disabled = true;
      post('/api/rules/' + encodeURIComponent(D.bus) + '/delete', {md5: D.md5})
        .then(function (j) {
          if (j.ok) { location.href = j.redirect; }
          else { showErr(j.error || 'refused'); rm.disabled = false; }
        });
    });
  }

  render();
})();
"""


LAST_EDIT = os.path.join(os.path.dirname(BACKUP_DIR.rstrip("/")) or "/run/netguard", "last-edit.json")


def remember_edit(payload: dict) -> None:
    payload = dict(payload, at=time.time())
    try:
        os.makedirs(os.path.dirname(LAST_EDIT), exist_ok=True)
        with open(LAST_EDIT, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except OSError as exc:
        log("cannot record last edit: %s" % exc)


def read_last_edit(bus_name: str) -> dict | None:
    try:
        with open(LAST_EDIT, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if data.get("bus") != bus_name:
        return None
    if time.time() - float(data.get("at") or 0) > 600:
        return None
    return data


def _split_current(policy: dict, members: list[dict]) -> tuple[list[dict], list[str]]:
    """Split an existing allowlist into checkbox picks and untouched literals."""
    if not policy:
        return [], []
    by_target = {}
    for m in members:
        by_target[m["write_as"]] = m
        by_target[m["name"]] = m
    picks, keep = [], []
    for entry in policy["entries"]:
        target, port = split_entry(entry)
        member = by_target.get(target)
        if member is None:
            keep.append(entry)
        else:
            picks.append({"target": member["write_as"], "port": port or ""})
    return picks, keep


def render_edit(model: dict, bus: dict) -> str:
    name = bus["name"]
    p = bus["policy"]
    picks, keep = _split_current(p, bus["members"])
    picked = {x["target"]: x["port"] for x in picks}
    cur_shape = "callers" if (p and p["dir"] == "src") else "servers"
    cur_mode = model["conf"]["modes"].get(name, "enforce") if p else "observe"

    data = {
        "bus": name,
        "md5": model["conf"]["md5"],
        "members": bus["member_count"],
        "keep": keep,
        "exists": bool(p),
    }

    rows = []
    for m in sorted(bus["members"], key=lambda x: x["name"].lower()):
        alias = m["write_as"]
        shown = esc(alias)
        extra = ""
        if alias != m["name"]:
            extra = ' <span class="mut" style="font-size:.78rem">%s &middot; %s</span>' % (
                esc(m["name"]), esc(m["ip"] or "—"))
        else:
            extra = ' <span class="mut" style="font-size:.78rem">%s</span>' % esc(m["ip"] or "—")
        checked = " checked" if alias in picked else ""
        port = picked.get(alias, "")
        rows.append(
            '<div class="prow" data-target="%s">'
            '<label><input type="checkbox" value="%s"%s>'
            '<span class="mono">%s</span>%s</label>'
            '<input class="port" value="%s" placeholder="any port" inputmode="numeric">'
            "</div>" % (esc(alias), esc(alias), checked, shown, extra, esc(port))
        )

    keep_note = ""
    if keep:
        keep_note = (
            '<div class="note" style="margin-top:6px">Carried through unchanged '
            "(not editable here — literal addresses): %s</div>"
            % ", ".join("<code>%s</code>" % esc(k) for k in keep)
        )

    body = render_header(
        model,
        {
            "title": "Rule for %s" % name,
            "sub": '<a href="/bus/%s">&larr; %s</a> · %s · %d members%s'
            % (urllib.parse.quote(name), esc(name), esc(bus["subnet"] or "?"),
               bus["member_count"], "" if p else " · currently unguarded"),
        },
    )
    if not WRITE_ENABLED:
        body += (
            '<div class="card"><div class="plain">Editing is disabled on this deployment '
            "(<code>NETGUARD_WRITE</code> is not 1). The page stays read-only.</div></div>"
        )
        return render_page("net-guard · %s" % name, body)

    body += (
        '<div id="err" class="warn-item bad" style="display:none"></div>'
        '<div class="lbl">1 &middot; what should be allowed on this bus?</div>'
        '<label class="opt"><input type="radio" name="shape" value="callers"%s>'
        "<div><b>Only these apps may start traffic</b>"
        "<em>One caller, many targets — trafficjam's old shape. Everyone else on the bus "
        "can start nothing.</em></div></label>"
        '<label class="opt"><input type="radio" name="shape" value="servers"%s>'
        "<div><b>Anyone may connect, but only to these apps</b>"
        "<em>Many callers, few privileged servers. Restrictions apply per destination and "
        "can name a port.</em></div></label>"
        '<div class="lbl">2 &middot; which apps?</div>'
        '<div class="picker">%s</div>%s'
        '<div class="lbl">3 &middot; how strictly?</div>'
        '<label class="opt"><input type="radio" name="mode" value="observe"%s>'
        "<div><b>Observe</b><em>Block nothing yet — log every flow that the rule would cut, "
        "so you can see the damage before it happens.</em></div></label>"
        '<label class="opt"><input type="radio" name="mode" value="enforce"%s>'
        "<div><b>Enforce</b><em>Actually drop non-allowed flows on this bus.</em></div></label>"
        '<div class="lbl">result</div><div id="preview" class="prevbox"></div>'
        '<div class="actions"><button id="save" class="btn pri">Save &amp; apply</button>%s'
        '<span class="note">Applies within 60s — the guard reloads its config, no restart. '
        "You still commit the file.</span></div>"
        '<script type="application/json" id="ng-data">%s</script>'
        '<script src="/app.js"></script>'
        % (
            " checked" if cur_shape == "callers" else "",
            " checked" if cur_shape == "servers" else "",
            "".join(rows),
            keep_note,
            " checked" if cur_mode == "observe" else "",
            " checked" if cur_mode == "enforce" else "",
            '<button id="remove" class="btn bad">Remove rule</button>' if p else "",
            json.dumps(data).replace("</", "<\\/"),
        )
    )
    return render_page("net-guard · rule %s" % name, body)


def render_error(message: str) -> str:
    body = (
        "<div class=top><div><h1>net-guard</h1>"
        "<div class=sub>cannot render this page</div></div></div>"
        "<div class=card><div class=plain>%s</div>"
        '<div class=note><a href="/">back to the bus list</a></div></div>' % esc(message)
    )
    return render_page("net-guard · error", body)


# ─── http ─────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "netguard/1"
    sys_version = ""

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Inline <style> only; no script anywhere, so nothing to allow for scripts.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_html(self, body: str, status: int = 200) -> None:
        self._send(status, body.encode("utf-8"), "text/html; charset=utf-8")

    def send_json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj, indent=2, sort_keys=True).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802 - probes and proxies often send HEAD
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain; charset=utf-8")
            if path == "/app.js":
                return self._send(200, APP_JS.encode("utf-8"), "application/javascript; charset=utf-8")
            if path == "/api/state":
                return self.send_json(build_model())
            if path == "/api/widget":
                return self.send_json(build_widget())
            if path in ("/", ""):
                return self.send_html(render_list(build_model()))
            if path.startswith("/bus/"):
                rest = urllib.parse.unquote(path[len("/bus/"):]).strip("/")
                model = build_model()
                if rest.endswith("/edit"):
                    name = rest[: -len("/edit")].strip("/")
                    bus = next((b for b in model["buses"] if b["name"] == name), None)
                    if bus is None:
                        return self.send_html(render_error("no bus named %r" % name), 404)
                    return self.send_html(render_edit(model, bus))
                bus = next((b for b in model["buses"] if b["name"] == rest), None)
                if bus is None:
                    return self.send_html(render_error("no bus named %r" % rest), 404)
                return self.send_html(
                    render_detail(model, bus, saved=query.get("saved", ["0"])[0] == "1")
                )
            return self.send_html(render_error("not found: %s" % path), 404)
        except DockerError as exc:
            log("docker error: %s" % exc)
            return self.send_html(render_error(str(exc)), 503)
        except Exception as exc:  # noqa: BLE001 - a firewall view must never 500 silently
            log("unhandled: %s\n%s" % (exc, traceback.format_exc()))
            return self.send_html(render_error("%s: %s" % (type(exc).__name__, exc)), 500)

    def _json_body(self) -> dict:
        """Read and screen a JSON body.

        CSRF, in two layers: a browser cannot send `application/json` cross-origin
        without a CORS preflight (we send no CORS headers, so it fails), and an
        Origin/Referer that names another site is refused outright.
        """
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise RuleError("expected Content-Type: application/json (got %r)" % ctype)
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if origin and host and origin not in ("https://" + host, "http://" + host):
            raise RuleError("cross-origin request refused")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 65536:
            raise RuleError("request body must be 1..64 KiB")
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError as exc:
            raise RuleError("body is not JSON: %s" % exc)

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        try:
            if not WRITE_ENABLED:
                raise RuleError("editing is disabled on this deployment (NETGUARD_WRITE is not 1)")
            payload = self._json_body()
            model = build_model()

            if path == "/api/rules":
                bus = str(payload.get("bus") or "")
                result = write_rule(
                    model,
                    bus,
                    str(payload.get("shape") or ""),
                    payload.get("allow") or [],
                    str(payload.get("mode") or ""),
                    payload.get("md5"),
                    payload.get("keep") or [],
                )
                remember_edit(dict(result, bus=bus))
                return self.send_json(
                    {
                        "ok": True,
                        "message": result["message"],
                        "redirect": "/bus/%s?saved=1" % urllib.parse.quote(bus),
                    }
                )

            m = re.match(r"^/api/rules/([^/]+)/(delete|mode|allow-flow)$", path)
            if m:
                bus = urllib.parse.unquote(m.group(1))
                action = m.group(2)
                if action == "delete":
                    result = delete_rule(model, bus, payload.get("md5"))
                elif action == "mode":
                    result = set_rule_mode(model, bus, str(payload.get("mode") or ""), payload.get("md5"))
                else:
                    result = allow_flow(model, bus, payload)
                remember_edit(dict(result, bus=bus))
                return self.send_json(
                    {
                        "ok": True,
                        "message": result["message"],
                        "redirect": "/bus/%s?saved=1" % urllib.parse.quote(bus),
                    }
                )
            raise RuleError("unknown endpoint %s" % path)
        except RuleError as exc:
            return self.send_json({"ok": False, "error": str(exc)}, status=400)
        except OSError as exc:
            log("write failed: %s" % exc)
            return self.send_json({"ok": False, "error": "write failed: %s" % exc}, status=500)
        except Exception as exc:  # noqa: BLE001
            log("POST unhandled: %s\n%s" % (exc, traceback.format_exc()))
            return self.send_json({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}, status=500)

    def log_message(self, fmt: str, *args) -> None:  # quieter than the default
        log("%s %s" % (self.address_string(), fmt % args))


def main() -> int:
    host, _, port = LISTEN.rpartition(":")
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port or 8080)), Handler)
    server.daemon_threads = True
    log("listening on %s; guard config %s; state %s; docker %s"
        % (LISTEN, GUARD_CONF, GUARD_STATE_DIR, DOCKER_HOST))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
