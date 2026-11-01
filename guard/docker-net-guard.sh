#!/bin/sh
# docker-net-guard — the host's east-west firewall for docker networks.
#
# It owns THREE jobs, all of them trafficjam's before 2026-10-30:
#   1. per-BUS policy (the POLICIES list below), in filter/DOCKER-USER;
#   2. `proxy` — the one bus trafficjam guarded, now just the policy entry
#      `proxy src 10.10.10.0/24 traefik` (same three rules, rule for rule);
#   3. CROSS-BRIDGE isolation, host-wide, in raw/PREROUTING (see that section).
#
# WHY THE POLICY CHAINS EXIST: a whitelist keyed on --source (trafficjam's model:
# one `--source $IP --destination $SUBNET --jump RETURN` per whitelisted
# container) is a fan-IN shape — ONE privileged initiator (traefik) reaching many
# targets on `proxy`. Several buses here are the INVERSE: many untrusted
# initiators reaching a few privileged DESTINATIONS, where a source whitelist is
# either a no-op (whitelist the apps => everyone reaches everyone) or
# self-defeating (whitelist the proxies => the final
# `--source $SUBNET --destination $SUBNET --jump DROP` still drops all
# app->proxy traffic, breaking DOCKER_HOST). No trafficjam env var inverted that.
# So each policy picks its own selector, and `proxy` simply uses `src`.
#
# HISTORICAL, and still the reason this is its own container: the trafficjam
# binary is not usable as a library here — its TRAFFICJAM chain name is a
# hardcoded literal, so a second instance inserts into the SAME chain, and the
# `DOCKER-USER -> TRAFFICJAM` jump is added bare (no comment) while
# remove_old_rules greps `--comment "trafficjam_$INSTANCE_ID"` — so that jump was
# unremovable by either instance and teardown leaked a dangling jump. This script
# keeps trafficjam's RULE SHAPE, not its process.
#
# POLICY GRAMMAR (GUARD_POLICIES, space-separated entries):
#     <name>:<direction>:<subnet>:<allowlist>
#   direction  src | dst  — which side of the match the allowlist applies to.
#                          src = allowlisted containers may initiate anywhere on
#                          the subnet (trafficjam's model; use when ONE app is the
#                          sole initiator). dst = any container on the subnet may
#                          reach ONLY the allowlisted destinations (use when many
#                          untrusted initiators front few privileged targets).
#   subnet     e.g. 10.10.20.0/24
#   allowlist  comma-separated entries, each:
#                <ip>          literal address
#                <ip>:<port>   literal address, one TCP port
#                <alias>       docker network alias, resolved live via the
#                              read-only socket proxy each poll (an alias may
#                              also be <alias>:<port>). Resolution exists so a
#                              policy need not hardcode an address that IPAM could
#                              steal at boot.
#
# MODES (GUARD_MODE, comma-separated names, defaults to all):
#   <name>:enforce  conntrack RETURN, allowlist RETURN, then DROP the subnet.
#   <name>:observe  same, but LOG each would-be-dropped flow then RETURN, so the
#                   real traffic can be measured before enforcement. Reads are
#                   host-side (the container cannot read the kernel ring buffer:
#                   kernel.dmesg_restrict=1):
#                     dmesg -T | grep docker-net-guard
#
# SAFETY: a policy whose allowlist resolves to EMPTY is refused and the previous
# ruleset for that chain is kept. Falling back to an empty allowlist would DROP
# every flow on the bus (or, in observe mode, silently measure nothing), so the
# guard fails closed toward "leave it alone and complain" instead. Refusing is
# PER-POLICY and non-fatal: every other policy still installs and the guard keeps
# running (see for_each_policy — letting this abort was a crash-loop bug).
#
# LIVE RELOAD: $GUARD_CONFIG is re-read whenever its md5 changes, checked once per
# poll, so an edit applies within POLL_INTERVAL and needs NO container restart. The
# new file is parsed in a subshell and validated with the same grammar as boot; a
# bad edit is refused (reason logged) and the running policy is kept. A policy that
# is DELETED from the file has its chain explicitly cleared — otherwise it would keep
# enforcing a rule no longer in the config, since only SIGTERM/cleanup removes chains.
#
# STATUS: the effective state (per-policy mode, resolved allowlist, hook presence,
# rule counts, refusals, DOCKER-USER jumps, cross-bridge summary) is published as
# JSON to $GUARD_STATE_DIR on every build and every poll. That is what the netguard
# UI (compose/admin/netguard) reads — the log below only prints on CHANGE, so it can
# never answer "are the chains installed right now?". Publication is optional: with
# no mount the guard runs unchanged and just skips writing.
#
# DOCKER_HOST: this container is network_mode:host, where docker's embedded DNS
# does not exist, so the pinned read-only proxy IP is mandatory — a bare
# `socket-proxy` hostname is unresolvable here. Read-only SP_ALLOW_GET already
# permits `containers`, which is all alias resolution needs.
#
# Rollback: SIGTERM/SIGINT clears every chain this script owns (below). For a hard
# `docker kill` the rules persist, which is the safe direction; clear by hand:
#   docker exec socket-net-guard iptables -D DOCKER-USER -j DOCKERNET_GUARD
#   docker exec socket-net-guard iptables -F DOCKERNET_GUARD
#   docker exec socket-net-guard iptables -X DOCKERNET_GUARD
set -eu

# The single chain all policy chains are jumped from, plus the tag every rule this
# script owns carries so teardown can never touch someone else's rules.
ROOT_CHAIN=DOCKERNET_GUARD
RULE_TAG=docker-net-guard

log() { echo "[docker-net-guard] $*"; }
die() { log "FATAL: $*"; exit 1; }

IPT="$(command -v iptables || true)"
[ -n "$IPT" ] || die "iptables not found in image — cannot program the ruleset"
DOCKER="$(command -v docker || true)"
# `ip` is needed by the cross-bridge chain only (it reads the host interface
# table). Missing it must NOT abort the guard: dying here would crash-loop, and
# every cycle's SIGTERM runs cleanup() and tears all policy chains down with it —
# far worse than one degraded control. build_xbridge reports it instead.
IPBIN="$(command -v ip || true)"
# `dmesg` is an APPETITE, not a dependency: without CAP_SYSLOG (or on an image that
# ships no busybox applet) the guard must still run. observed_json reports it.
DMESG="$(command -v dmesg || true)"

# Single source of truth for policy. The config file is shell-sourced rather than
# parsed as YAML because this image has no python/jq/yq (busybox only), and a
# hand-rolled parser for something that installs firewall rules is not worth the
# risk. If it is missing the guard refuses to start rather than running with no
# policy, because "no policy installed" means the buses are silently open.
CONFIG="${GUARD_CONFIG:-/etc/docker-net-guard.conf}"
# Where write_status publishes. Optional: no mount => no publication, and the guard
# behaves exactly as it did before.
STATE_DIR="${GUARD_STATE_DIR:-/state}"
# md5 of the config that is CURRENTLY PROGRAMMED, as opposed to what the file says
# right now. reload_if_changed compares the two. Deliberately NOT advanced on a refused
# reload: "on disk differs from applied" must stay TRUE so a reader (the netguard UI,
# status.json) can tell that an edit has not taken effect, and why.
CONFIG_MD5=""
# md5 of the last config REFUSED, only to keep the log from repeating every poll while
# a bad edit sits there (it is still re-parsed each poll, and heals the moment it is fixed).
REFUSED_MD5=""
RELOAD_ERR=""
GENERATION=0
POL_ERR=""
POLL=60
GUARD_STARTED=$(date +%s)

config_md5() { md5sum "$CONFIG" 2>/dev/null | awk '{print $1}'; }

# config_field <VAR> — source the config in a SUBSHELL and print one variable.
# The subshell is the whole point of this helper: a syntax error, a bad command or a
# stray `exit` in an edit can then only kill the subshell, never the guard that is
# still enforcing the previous policy. Sourcing in the main shell (what the first
# revision did, harmlessly, at boot) means one typo takes the firewall down on the
# next reload.
config_field() {
  ( set -eu; . "$CONFIG"; case "$1" in
      POLICIES)      printf '%s' "$POLICIES" ;;
      MODES)         printf '%s' "${MODES:-}" ;;
      POLL_INTERVAL) printf '%s' "${POLL_INTERVAL:-}" ;;
    esac ) 2>/dev/null
}

# The config authors POLICIES as space-separated 4-field groups:
#   <name> <direction> <subnet> <allowlist>   x N
# Walk it as fields, not as colon-joined specs — word splitting is what makes the
# file readable, and re-joining on ':' would break the moment an allowlist entry
# contained one. Validate here so a typo fails loudly instead of silently producing
# a chain with no allowlist (which would DROP the whole bus).
# Reports through POL_ERR instead of dying, so the reload path can refuse a bad edit
# while the boot path still calls die().
parse_policies() {
  POLICY_TOKENS=""
  POLICY_NAMES=""
  set -- $1
  while [ "$#" -gt 0 ]; do
    [ "$#" -ge 4 ] || { POL_ERR="incomplete policy definition in $CONFIG: got ($*) — expected 4 fields"; return 1; }
    name=$1 dir=$2 subnet=$3 allow=$4
    shift 4
    case "$dir" in
      src|dst) ;;
      *) POL_ERR="policy '$name': direction must be src or dst (got '$dir')"; return 1 ;;
    esac
    case "$subnet" in
      */*) ;;
      *) POL_ERR="policy '$name': subnet must be CIDR (got '$subnet')"; return 1 ;;
    esac
    [ -n "$allow" ] || { POL_ERR="policy '$name': empty allowlist"; return 1; }
    POLICY_TOKENS="$POLICY_TOKENS $name $dir $subnet $allow"
    POLICY_NAMES="$POLICY_NAMES $name"
  done
  [ -n "$(printf '%s' "$POLICY_TOKENS" | tr -d ' ')" ] || { POL_ERR="no policies defined in $CONFIG"; return 1; }
  return 0
}

# load_config — read $CONFIG into POLICIES/MODES/POLL and the parsed policy lists.
# Returns 1 with POL_ERR set; never exits, so both boot and reload share one parser.
load_config() {
  POL_ERR=""
  [ -r "$CONFIG" ] || { POL_ERR="config file $CONFIG is missing or unreadable"; return 1; }
  _pol=$(config_field POLICIES) || { POL_ERR="config $CONFIG did not parse (shell error while sourcing)"; return 1; }
  parse_policies "$_pol" || return 1
  POLICIES="$_pol"
  MODES=$(config_field MODES) || MODES=""
  _poll=$(config_field POLL_INTERVAL) || _poll=""
  case "$_poll" in
    ''|*[!0-9]*) ;;
    *) POLL="$_poll" ;;
  esac
  return 0
}

load_config || die "$POL_ERR — refusing to start with no policy"
CONFIG_MD5=$(config_md5)
[ -n "$CONFIG_MD5" ] || log "WARNING: md5sum unavailable — live config reload is disabled"

# resolve_alias <network> <alias> -> IP on stdout, empty if not found.
# Emits one "<alias> <ip>" line per (container, alias) pair on that network, then
# filters for the requested alias. Uses a single `docker inspect` over every
# member, so the cost does not scale with the number of aliases.
#
# Note Docker also lists the container name in .Aliases, so a container is
# addressable by its container_name as well as by any explicit -widget alias.
resolve_alias() {
  net="$1" want="$2"
  [ -n "$DOCKER" ] || return 0
  ids=$("$DOCKER" ps --filter "network=$net" --format '{{.ID}}' 2>/dev/null || true)
  [ -n "$ids" ] || return 0
  printf '%s\n' "$ids" | xargs -r "$DOCKER" inspect --format \
    '{{range $n,$v := .NetworkSettings.Networks}}{{if eq $n "'"$net"'"}}{{range $v.Aliases}}{{println . " " $v.IPAddress}}{{end}}{{end}}{{end}}' \
    2>/dev/null | while read -r a ip; do
      [ "$a" = "$want" ] && { echo "$ip"; break; }
    done
}

# expand_allowlist <network> <allowlist-csv> -> normalized " ip[:port] ..." list.
# Aliases are resolved live; bare IPs pass through. This is deliberately separate
# from build_policy so the poll loop can compute the SAME list and compare it with
# what is installed, which is what makes drift detectable. An unresolvable alias
# is simply omitted here — callers decide whether an empty result is fatal
# (build_policy refuses to install; the poll leaves the rules alone).
expand_allowlist() {
  net="$1" allowlist="$2"
  out=""
  for entry in $(printf '%s' "$allowlist" | tr ',' ' '); do
    [ -n "$entry" ] || continue
    target="$entry"; port=""
    case "$entry" in
      *:*) target="${entry%%:*}"; port="${entry##*:}" ;;
    esac
    case "$target" in
      *[!0-9.]*)
        got=$(resolve_alias "$net" "$target" | head -1)
        [ -n "$got" ] || continue
        if [ -n "$port" ]; then out="$out $got:$port"; else out="$out $got"; fi
        ;;
      *) out="$out $entry" ;;
    esac
  done
  printf '%s' "$out"
}

# normalize_ips " ip[:port] ..." -> canonical, comparable form.
# Sorts the entries so ordering never registers as drift, and joins with a
# delimiter that cannot be confused with the list separator. NOTE: do NOT use
# `tr -d ' '` here — the space IS the separator, so deleting it glues entries
# together ("10.10.20.200:237510.10.20.201:2375").
normalize_ips() {
  printf '%s' "$1" | tr ' ' '\n' | grep -v '^$' | sort | paste -sd, - 2>/dev/null || \
    printf '%s' "$1" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ','
}

# mode_for <policy-name> -> enforce | observe
mode_for() {
  case ",$MODES," in
    *",$1:observe,"*) echo observe ;;
    *) echo enforce ;;
  esac
}

# clear_policy <chain> <subnet>
clear_policy() {
  chain="$1"; subnet="$2"
  while "$IPT" -t filter -C DOCKER-USER -j "$chain" 2>/dev/null; do
    "$IPT" -t filter -D DOCKER-USER -j "$chain" 2>/dev/null || break
  done
  if "$IPT" -t filter -L "$chain" >/dev/null 2>&1; then
    "$IPT" -t filter -F "$chain" 2>/dev/null || true
    "$IPT" -t filter -X "$chain" 2>/dev/null || true
  fi
  : "$subnet"
}

# build_policy — reads $name/$dir/$subnet/$allow set by for_each_policy. (It
# deliberately does NOT take them as positional args: the caller runs it with none,
# and declaring $1..$4 here under `set -u` aborts the guard at boot.)
build_policy() {
  chain="DOCKERNET_${name}"

  ips=$(expand_allowlist "$name" "$allow")

  # SAFETY: never install an empty allowlist. It would drop every flow on the
  # subnet (enforce) or silently log nothing (observe).
  if [ -z "$(normalize_ips "$ips")" ]; then
    log "$name: refusing to install — allowlist resolved empty"
    printf 'refused' > "/tmp/.docker-net-guard.$name.state" 2>/dev/null || true
    return 1
  fi

  clear_policy "$chain" "$subnet"
  "$IPT" -t filter -N "$chain"

  # 1. Replies to established flows, so a rebuild never cuts live connections.
  "$IPT" -t filter -A "$chain" -s "$subnet" -d "$subnet" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN \
    -m comment --comment "$RULE_TAG/$name"

  # 2. The allow policy. `dir` selects which side of the match it applies to.
  for entry in $ips; do
    ip="${entry%%:*}"; port=""
    case "$entry" in *:*) port="${entry##*:}" ;; esac
    if [ "$dir" = src ]; then
      set -- -s "$ip" -d "$subnet"
    else
      set -- -s "$subnet" -d "$ip"
    fi
    if [ -n "$port" ] && [ "$port" != "*" ]; then
      "$IPT" -t filter -A "$chain" "$@" -p tcp --dport "$port" -j RETURN \
        -m comment --comment "$RULE_TAG/$name"
      log "$name[$dir]: allow $ip:$port"
    else
      "$IPT" -t filter -A "$chain" "$@" -j RETURN \
        -m comment --comment "$RULE_TAG/$name"
      log "$name[$dir]: allow $ip (any port)"
    fi
  done

  # 3. Terminal rule. observe logs instead of dropping, so real traffic can be
  #    measured before enforcement.
  mode=$(mode_for "$name")
  if [ "$mode" = observe ]; then
    "$IPT" -t filter -A "$chain" -s "$subnet" -d "$subnet" \
      -j LOG --log-prefix "docker-net-guard/$name: " \
      -m comment --comment "$RULE_TAG/$name"
    "$IPT" -t filter -A "$chain" -s "$subnet" -d "$subnet" -j RETURN \
      -m comment --comment "$RULE_TAG/$name"
    log "$name: OBSERVE (logging, not dropping)"
  else
    "$IPT" -t filter -A "$chain" -s "$subnet" -d "$subnet" -j DROP \
      -m comment --comment "$RULE_TAG/$name"
    log "$name: ENFORCE (dropping all other $subnet traffic)"
  fi

  "$IPT" -t filter -C DOCKER-USER -j "$chain" 2>/dev/null || \
    "$IPT" -t filter -I DOCKER-USER 1 -j "$chain"

  # One authoritative line naming the EFFECTIVE policy, so drift or a wrong
  # resolution is visible in the log instead of having to be inferred from rules.
  log "$name[$dir/$mode]: effective=$(normalize_ips "$ips")"
  # Record what was installed so the poll can detect an address changing under us.
  # /tmp is tmpfs and this container is read-only elsewhere, so it is the only
  # writable path; losing it on restart is harmless (the next poll re-resolves and
  # treats an empty "installed" as drift, which triggers exactly one rebuild).
  normalize_ips "$ips" > "/tmp/.docker-net-guard.$name.ips"
  # Published verbatim in status.json so an operator (or the UI) can see WHICH state
  # a bus is in without reading iptables: ok | refused | unresolved.
  printf 'ok' > "/tmp/.docker-net-guard.$name.state" 2>/dev/null || true
}

################################################################################
# CROSS-BRIDGE ISOLATION (raw/PREROUTING)
################################################################################
# The per-policy chains above match `-s <subnet> -d <subnet>`, so they only see
# traffic whose source AND destination are on the SAME bus. They cannot stop one
# container reaching another container on a DIFFERENT bridge, and without that
# property every container on this host can reach every other one (the docker
# FORWARD path allows it, and no policy chain matches a cross-bus pair).
#
# This used to be trafficjam's second job: one rule per CONTAINER,
# `-d <container ip>/32 ! -i <its bridge> -j DROP`, 266 of them at the fold,
# rebuilt from the Docker API on every poll. Here the same property is rebuilt
# from the HOST interface table instead, which is cheaper and steadier:
#   * a bridge's own address IS its subnet's gateway, so one read of
#     `ip -o -4 addr show` yields (interface, subnet, gateway) for every bridge —
#     no Docker API, no per-container bookkeeping, nothing to reconcile when a
#     container is recreated;
#   * the set is per NETWORK (2 rules per bridge, 83 for 41 bridges today) rather
#     than per container (266 and growing), so the bug class that once grew trafficjam's
#     chain to 961 rules cannot exist here;
#   * a container that starts between polls is covered immediately, because its
#     subnet already is.
#
# Semantics deliberately match the per-container form:
#   * a bridge GATEWAY stays reachable from anywhere. That is how a container
#     reaches host-published ports (>ALLOW_HOST_TRAFFIC=true< in trafficjam
#     terms), and it is why a naive `-i br-+ -j DROP` would be wrong;
#   * 127.0.0.0/8 is never a valid cross-bridge destination. trafficjam
#     generated one rule per loopback-published port (crowdsec :9876,
#     ha-mosquitto :1883); the range rule covers those and any future one
#     without asking the Docker API.
#
# cleanup() does NOT flush this chain: unlike a policy chain it is idempotent, so
# leaving it hooked means a guard restart has no window where the host is open,
# and a stopped guard fails CLOSED. Clear it by hand if the guard is retired:
#   docker exec socket-net-guard iptables -t raw -D PREROUTING -j DOCKERNET_XBRIDGE
#   docker exec socket-net-guard iptables -t raw -F DOCKERNET_XBRIDGE
#   docker exec socket-net-guard iptables -t raw -X DOCKERNET_XBRIDGE
XBRIDGE_CHAIN=DOCKERNET_XBRIDGE
XBRIDGE_TAG="$RULE_TAG/xbridge"
XBRIDGE_STATE=/tmp/.docker-net-guard-xbridge.spec

# Prints "<iface> <addr/len>" per docker bridge. `-o` puts the interface in
# field 2 and the address in field 4; matching on `$2 ~ /^br-/` is what makes
# this docker-only (a macvlan/ipvlan network has no br-* and is not covered,
# exactly as trafficjam's per-container rules did not cover them either).
xbridge_specs() {
  [ -n "$IPBIN" ] || return 0
  "$IPBIN" -o -4 addr show 2>/dev/null | awk '$2 ~ /^br-/ && $3 == "inet" {print $2, $4}'
}

build_xbridge() {
  if [ -z "$IPBIN" ]; then
    log "cross-bridge: 'ip' is missing from the image — NOT installed (cross-bridge traffic is unfiltered)"
    return 1
  fi
  specs=$(xbridge_specs)
  if [ -z "$specs" ]; then
    log "cross-bridge: no br-* interfaces found — refusing to build (previous rules kept, or the host is OPEN if none were ever installed)"
    return 1
  fi

  # First run creates the chain while nothing is hooked to it, so there is no
  # window at all. A later rebuild happens only when the bridge/subnet set
  # changed (a docker network create/remove), and costs a sub-second gap between
  # the flush and the last rule while the chain is still hooked.
  if "$IPT" -t raw -L "$XBRIDGE_CHAIN" >/dev/null 2>&1; then
    "$IPT" -t raw -F "$XBRIDGE_CHAIN"
  else
    "$IPT" -t raw -N "$XBRIDGE_CHAIN"
  fi

  # 1. Gateways first: no later DROP may swallow host-published traffic.
  printf '%s\n' "$specs" | while read -r iface cidr; do
    "$IPT" -t raw -A "$XBRIDGE_CHAIN" -d "${cidr%%/*}/32" \
      -m comment --comment "$XBRIDGE_TAG" -j RETURN
  done
  # 2. A docker subnet is reachable only from its own bridge. iptables masks the
  #    host address back to the network (10.70.1.1/24 -> 10.70.1.0/24).
  printf '%s\n' "$specs" | while read -r iface cidr; do
    "$IPT" -t raw -A "$XBRIDGE_CHAIN" -d "$cidr" ! -i "$iface" \
      -m comment --comment "$XBRIDGE_TAG" -j DROP
  done
  # 3. Loopback is never a cross-bridge destination.
  "$IPT" -t raw -A "$XBRIDGE_CHAIN" -d 127.0.0.0/8 ! -i lo \
    -m comment --comment "$XBRIDGE_TAG" -j DROP

  # Insert at position 1: nothing else owns raw/PREROUTING today, and being first
  # only makes the drop earlier. A packet that matches no rule falls through the
  # chain and continues after the jump, so a co-existing rule set still runs.
  "$IPT" -t raw -C PREROUTING -j "$XBRIDGE_CHAIN" 2>/dev/null || \
    "$IPT" -t raw -I PREROUTING 1 -j "$XBRIDGE_CHAIN"

  printf '%s\n' "$specs" > "$XBRIDGE_STATE"
  bridges=$(printf '%s\n' "$specs" | grep -c 'br-' || true)
  log "cross-bridge: ENFORCE $bridges bridges -> $((bridges * 2 + 1)) rules"
}

# Body for the cross-bridge check inside watch(). Sets $xb_restart=1 to rebuild.
verify_xbridge() {
  want=$(xbridge_specs)
  if [ -z "$want" ]; then
    # Same contract as a policy whose allowlist failed to resolve: keep what is
    # installed rather than tearing down a working control over one bad read.
    log "cross-bridge: no br-* interfaces this poll — keeping installed rules"
    return
  fi
  if ! "$IPT" -t raw -C PREROUTING -j "$XBRIDGE_CHAIN" 2>/dev/null; then
    log "cross-bridge: PREROUTING hook missing — rebuilding"
    xb_restart=1
    return
  fi
  have=$(cat "$XBRIDGE_STATE" 2>/dev/null || echo "")
  if [ "$(printf '%s\n' "$want")" != "$have" ]; then
    log "cross-bridge: DRIFT (bridge/subnet set changed) — rebuilding"
    xb_restart=1
    return
  fi
  # Structure check: losing the DROP (or a gateway RETURN) leaves the host open
  # while the chain still looks present, so count the tagged rules.
  bridges=$(printf '%s\n' "$want" | grep -c 'br-' || true)
  got=$("$IPT" -t raw -S "$XBRIDGE_CHAIN" 2>/dev/null | grep -cF -- "$XBRIDGE_TAG" || true)
  if [ "$got" != "$((bridges * 2 + 1))" ]; then
    log "cross-bridge: rule count $got != $((bridges * 2 + 1)) — rebuilding"
    xb_restart=1
  fi
}

# Iterate policies as 4-field groups (name direction subnet allowlist), setting
# $name/$dir/$subnet/$allow for the callback. MUST be defined before build_all runs
# — a previous revision lost it in an edit and the guard crash-looped on
# "for_each_policy: not found", which is the worst possible failure mode here
# because the SIGTERM from the restart flushed every chain first.
for_each_policy() {
  # Capture the callback BEFORE `set --` overwrites the positional parameters,
  # which hold the policy tokens. Losing it makes "$@" re-run the next policy's
  # NAME as a command, e.g. "homepage_widgets: not found".
  _fn=$1; shift
  # A callback may REFUSE its own policy — build_policy returns 1 when the
  # allowlist resolves empty. That is a per-policy decision, not a fatal, so run
  # EVERY remaining policy regardless and report it through the return value.
  #
  # The `|| _rc=1` is load-bearing. Leaving the call bare means `set -e` aborts
  # the whole guard the moment one policy is refused, which is the worst failure
  # mode here (see the note on for_each_policy's ordering above): the container
  # crash-loops, and because `set -e` exits the shell directly the restart's
  # SIGTERM never reaches cleanup() either — so each cycle re-installed the
  # policies that DID resolve while leaving the refused one stale in the host
  # ruleset, with nothing in the logs but one repeated line. That is exactly
  # what happened: homepage_widgets' sole allowlist entry, `homepage`, is not a
  # member of the bus on every deployment, and one unresolvable alias took the
  # guard down with it. It also made build_policy's own SAFETY contract
  # ("refuse the policy, keep the previous ruleset") unreachable — the abort
  # happened before any other policy got a chance to install.
  _rc=0
  set -- $POLICY_TOKENS
  while [ "$#" -ge 4 ]; do
    name=$1 dir=$2 subnet=$3 allow=$4
    shift 4
    "$_fn" || _rc=1
  done
  return "$_rc"
}

build_all() {
  # Never propagate a refused policy upward: it must not stop the other buses
  # from being programmed. `return 0` makes that contract explicit — watch() runs
  # this inside its loop body, where a failure under `set -e`
  # would abort the poll loop and kill the guard.
  for_each_policy build_policy || \
    log ">=1 policy refused (see 'refusing to install' above) — those buses keep their previous ruleset, or stay UNFILTERED if none was installed yet"
  build_xbridge || \
    log "cross-bridge: NOT installed (see above) — traffic between containers on different bridges is unfiltered"
  # Publish straight after programming, so a reload is visible in status.json within
  # the same cycle that applied it rather than one poll later.
  write_status || true
  return 0
}

watch() {
  while true; do
    # Verify immediately rather than sleeping first: at start-up build_all has
    # just run, but on any later entry to watch() the chains may already have been
    # disturbed. A short first interval catches that within seconds instead of
    # leaving the bus open for a full poll period.
    [ -n "${_polled:-}" ] && sleep "$POLL" || _polled=1
    # An edited config is applied here, before verification: build_all at the end of
    # this cycle then programs the new policy, and verify_policy checks the NEW
    # ruleset rather than reporting drift against the old one.
    reload_if_changed
    # DOCKER-USER is rewritten by dockerd and by crowdsec's bouncer, and the
    # terminal rule is the load-bearing one — if either went missing the network is
    # silently open. Re-assert rather than trusting boot-time install.
    #
    # Match on the FULL rule line, not a bare "-j DROP": the rules we install are
    # suffixed with `-m comment --comment "docker-net-guard/<name>"`, so a pattern
    # anchored at end-of-line never matches and the chain looks permanently
    # healthy while its DROP is gone.
    restart=0
    xb_restart=0
    for_each_policy verify_policy
    verify_xbridge
    if [ "$restart" = 1 ]; then
      build_all                   # rebuilds the cross-bridge chain too
    elif [ "$xb_restart" = 1 ]; then
      build_xbridge || log "cross-bridge: rebuild refused (see above)"
    fi
    # Publish after the cycle, so the JSON always describes the ruleset as it is now.
    write_status || true
  done
}

# Body for one policy inside watch(). Sets $restart=1 to rebuild everything.
verify_policy() {
  chain="DOCKERNET_${name}"
  # Resolve ONCE, up front. Both the hook check and the drift check need it, and
  # it is the only part of this function that touches the Docker API.
  want=$(normalize_ips "$(expand_allowlist "$name" "$allow")")

  if ! "$IPT" -t filter -C DOCKER-USER -j "$chain" 2>/dev/null; then
    # No chain. Two very different causes, and only one is fixable from here:
    #   - allowlist resolves: dockerd or crowdsec's bouncer rewrote DOCKER-USER,
    #     so reinstall.
    #   - allowlist EMPTY: build_policy already refused this policy at startup and
    #     logged why. There is nothing to rebuild TO, and asking for a rebuild is
    #     actively harmful — build_all reinstalls EVERY policy, so one permanently
    #     unresolvable bus would tear down and recreate the healthy ones
    #     (socket_proxy, which guards the Docker API, included) on every poll,
    #     briefly unhooking its chain each time. Report and skip instead.
    if [ -z "$want" ]; then
      log "$name: allowlist still unresolved, still unfiltered — not rebuilding (see the startup log for why)"
      printf 'unresolved' > "/tmp/.docker-net-guard.$name.state" 2>/dev/null || true
      return
    fi
    log "$name: hook missing (dockerd/crowdsec rewrote DOCKER-USER) — rebuilding"
    restart=1
    return
  fi
  rules=$("$IPT" -t filter -S "$chain" 2>/dev/null | grep -F -- "$RULE_TAG/$name" || true)
  case "$(mode_for "$name")" in
    observe)
      # observe ends in LOG + RETURN; LOG is what makes the measurement real.
      echo "$rules" | grep -q -- "-j LOG" || {
        log "$name: LOG rule missing — rebuilding"; restart=1; return; }
      ;;
    *)
      echo "$rules" | grep -q -- "-j DROP" || {
        log "$name: DROP rule missing — rebuilding"; restart=1; return; }
      ;;
  esac
  # The allowlist is the other half of the policy; losing it would either
  # isolate the bus completely or (dst) silently permit everything. Every rule
  # in the chain carries this policy's comment immediately before its jump, so
  # the conntrack RETURN cannot be told from an allow entry by comment alone.
  # Require at least one RETURN that is neither the conntrack rule nor the
  # observe-mode trailing RETURN (which is preceded by LOG).
  if ! echo "$rules" | grep -v conntrack | grep -v -- "-j LOG" | grep -q -- "-j RETURN"; then
    log "$name: allowlist rules missing — rebuilding"; restart=1; return
  fi

  # DRIFT: an aliased address changes when its container is recreated, while
  # the chain still looks structurally perfect — hook present, terminal rule
  # present, allowlist RETURNs present — just pointing at a stale IP. Nothing
  # above detects that, so compare the freshly resolved allowlist against what
  # was last installed and rebuild on mismatch. Without this, a recreated
  # container stays locked out of the bus until some unrelated rule goes
  # missing. Stateful on purpose: the installed list is written by
  # build_policy, so the first poll after a crash-with-stale-/tmp still heals.
  have=$(cat "/tmp/.docker-net-guard.$name.ips" 2>/dev/null || echo "")
  if [ -z "$want" ]; then
    # Resolution failed transiently (flaky Docker API). Keep the installed
    # rules rather than tearing down a working policy over one bad call.
    log "$name: allowlist unresolved this poll — keeping installed rules"
    printf 'unresolved' > "/tmp/.docker-net-guard.$name.state" 2>/dev/null || true
  elif [ "$want" != "$have" ]; then
    log "$name: DRIFT (installed='$have' resolved='$want') — rebuilding"
    restart=1
  fi
}

################################################################################
# STATUS PUBLICATION
################################################################################
# One JSON document per build and per poll, written atomically (tmp + rename) so a
# reader never sees half of it. This exists because the log only prints on CHANGE:
# it can say what was installed an hour ago, never whether the chains are installed
# RIGHT NOW. The netguard UI reads it; so can a human, without exec'ing in.
#
# Fields are deliberately the ones a UI cannot derive from config + the Docker API:
# whether each chain is hooked, how many rules it holds, which bus is refused or
# unresolved, and which chains DOCKER-USER is currently jumping to.
#
# Values that reach the JSON come from the operator's config (names, subnets,
# allowlists), so they are escaped rather than trusted.
json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

write_status() {
  # Missing or read-only mount: publication is optional, never a reason to fail a
  # poll (the guard's job is the firewall, not the view).
  [ -d "$STATE_DIR" ] && [ -w "$STATE_DIR" ] || return 0
  _tmp="$STATE_DIR/.status.json.$$"
  {
    printf '{\n'
    printf '  "schema": 1,\n'
    printf '  "now": %s,\n' "$(date +%s)"
    printf '  "guard_started": %s,\n' "$GUARD_STARTED"
    printf '  "poll_interval": %s,\n' "$POLL"
    printf '  "generation": %s,\n' "$GENERATION"
    printf '  "config": {"path": "%s", "md5": "%s", "reload_error": "%s"},\n' \
      "$(json_str "$CONFIG")" "$CONFIG_MD5" "$(json_str "$RELOAD_ERR")"
    printf '  "policies": ['
    _sep=""
    set -- $POLICY_TOKENS
    while [ "$#" -ge 4 ]; do
      p_name=$1; p_dir=$2; p_subnet=$3; p_allow=$4; shift 4
      p_chain="DOCKERNET_${p_name}"
      p_ips=$(cat "/tmp/.docker-net-guard.$p_name.ips" 2>/dev/null || echo "")
      p_state=$(cat "/tmp/.docker-net-guard.$p_name.state" 2>/dev/null || echo "unknown")
      p_hooked=false
      "$IPT" -t filter -C DOCKER-USER -j "$p_chain" 2>/dev/null && p_hooked=true
      p_rules=$("$IPT" -t filter -S "$p_chain" 2>/dev/null | grep -c '^-A' || true)
      printf '%s\n    {"name": "%s", "dir": "%s", "subnet": "%s", "allow": "%s", "mode": "%s", "installed": "%s", "state": "%s", "hooked": %s, "rules": %s}' \
        "$_sep" "$(json_str "$p_name")" "$p_dir" "$p_subnet" "$(json_str "$p_allow")" \
        "$(mode_for "$p_name")" "$(json_str "$p_ips")" "$p_state" "$p_hooked" "${p_rules:-0}"
      _sep=","
    done
    printf '\n  ],\n'
    _xb_hooked=false
    "$IPT" -t raw -C PREROUTING -j "$XBRIDGE_CHAIN" 2>/dev/null && _xb_hooked=true
    _xb_bridges=$(xbridge_specs | grep -c 'br-' || true)
    _xb_rules=$("$IPT" -t raw -S "$XBRIDGE_CHAIN" 2>/dev/null | grep -cF -- "$XBRIDGE_TAG" || true)
    printf '  "xbridge": {"hooked": %s, "bridges": %s, "rules": %s},\n' \
      "$_xb_hooked" "${_xb_bridges:-0}" "${_xb_rules:-0}"
    printf '  "observed": %s,\n' "$(observed_json)"
    # Every target DOCKER-USER currently jumps to. This is how a retired chain that
    # someone re-created (trafficjam) or a lost hook shows up without guessing.
    printf '  "docker_user": ['
    _sep=""
    for _t in $("$IPT" -t filter -S DOCKER-USER 2>/dev/null | sed -n 's/.*-j \([A-Za-z0-9_]*\).*/\1/p'); do
      printf '%s"%s"' "$_sep" "$_t"
      _sep=","
    done
    printf ']\n'
    printf '}\n'
  } > "$_tmp" 2>/dev/null && mv -f "$_tmp" "$STATE_DIR/status.json" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
  return 0
}

# ── OBSERVED FLOWS (observe-mode evidence) ────────────────────────────────────
# The only place a would-be-dropped flow exists is the kernel ring buffer, which the
# guard can read with CAP_SYSLOG. Publishing it here (2026-11-02) rather than letting
# each reader parse dmesg has two payoffs: the netguard UI needs no kernel-log access
# at all (so it can run as uid 1000 and own the config it writes), and every consumer
# gets one parse per poll instead of one per request.
#
# LOG PREFIX, precisely: iptables truncates --log-prefix to 29 characters and
# "docker-net-guard/" is 17 of them, so a 12-character bus name consumes the rest and
# the trailing ": " is CUT — there is neither a colon nor a space before IN=
# (`docker-net-guard/downloadarrsIN=…`). A shorter name keeps the ": ". Both shapes
# are handled by cutting at "IN=", never at ":".
#
# Counters are per (bus, src, dst, proto, dport) over whatever the buffer currently
# holds, so they are a snapshot, not a history — the LOG rules have no --limit and a
# missing allowlist entry wraps the buffer quickly. `boot_at` lets a reader turn the
# kernel's seconds-since-boot into wall clock without another privileged read.
observed_json() {
  if [ -z "$DMESG" ]; then
    printf '{"ok": false, "error": "no dmesg in this image", "boot_at": 0, "flows": []}'
    return 0
  fi
  # busybox dmesg exits 1 and prints the reason on stderr when the capability is
  # missing; capture BOTH the status and the reason, so a silent failure cannot be
  # published as "zero flows" (which would read as a quiet bus).
  if _dmerr=$("$DMESG" 2>&1 1>/dev/null); then
    :
  else
    [ -n "$_dmerr" ] || _dmerr="dmesg failed"
    printf '{"ok": false, "error": "%s", "boot_at": 0, "flows": []}' \
      "$(json_str "$(printf '%s' "$_dmerr" | head -1)")"
    return 0
  fi
  _uptime=$(awk '{print int($1); exit}' /proc/uptime 2>/dev/null || echo 0)
  printf '{"ok": true, "error": "", "boot_at": %s, "flows": [' "$(( $(date +%s) - ${_uptime:-0} ))"
  _sep=""
  "$DMESG" 2>/dev/null | awk -v names="$POLICY_NAMES" '
    BEGIN {
      n = split(names, arr, " ")
      for (i = 1; i <= n; i++) {
        cut = substr(arr[i], 1, 12)
        # NB: NOT `bycut[cut] = (cut in bycut) ? ... : ...` — mawk creates the lvalue
        # element BEFORE evaluating the ternary, so `cut in bycut` is then true for a
        # key that was never set and the value gains a leading space (" downloadarrs"),
        # which silently breaks the bus-name match.
        if (!(cut in bycut)) bycut[cut] = arr[i]
      }
    }
    {
      i = index($0, "]")
      if (i < 2) next
      body = substr($0, i + 1)
      if (index(body, "docker-net-guard/") == 0) next
      ts = substr($0, 2, i - 2)
      gsub(/[^0-9.]/, "", ts)
      if (ts == "") next
      p = index(body, "IN=")
      head = (p > 1) ? substr(body, 1, p - 1) : body
      sub(/.*docker-net-guard\//, "", head)
      sub(/[ :].*$/, "", head)
      if (head == "") next
      bus = (head in bycut) ? bycut[head] : ""
      if (bus == "") {
        for (j = 1; j <= n; j++) if (substr(arr[j], 1, length(head)) == head) { bus = arr[j]; break }
      }
      if (bus == "") next
      src = ""; dst = ""; dpt = "0"; proto = "?"
      for (j = 1; j <= NF; j++) {
        if ($j ~ /^SRC=/) src = substr($j, 5)
        else if ($j ~ /^DST=/) dst = substr($j, 5)
        else if ($j ~ /^DPT=/) dpt = substr($j, 5)
        else if ($j ~ /^PROTO=/) proto = substr($j, 7)
      }
      if (src == "" || dst == "") next
      k = bus SUBSEP src SUBSEP dst SUBSEP proto SUBSEP dpt
      cnt[k]++
      if (!(k in first)) {
        first[k] = ts; busof[k] = bus; srcof[k] = src
        dstof[k] = dst; prtof[k] = proto; dptof[k] = dpt
      }
      last[k] = ts
    }
    END {
      for (k in cnt) printf "%s|%s|%s|%s|%s|%d|%.6f|%.6f\n", busof[k], srcof[k], dstof[k], prtof[k], dptof[k], cnt[k], first[k], last[k]
    }' | {
    _sep=""
    while IFS='|' read -r _b _s _d _pr _dp _c _f _l; do
      [ -n "$_b" ] || continue
      printf '%s{"bus": "%s", "src": "%s", "dst": "%s", "proto": "%s", "dport": "%s", "count": %s, "first": %s, "last": %s}' \
        "$_sep" "$_b" "$(json_str "$_s")" "$(json_str "$_d")" "$_pr" "$(json_str "$_dp")" "$_c" "$_f" "$_l"
      _sep=","
    done
  }
  printf ']}'
}

################################################################################
# LIVE RELOAD
################################################################################
# Apply an edited config without a container restart. Before this, $GUARD_CONFIG was
# sourced once at start, so an edit needed `docker restart socket-net-guard` and a
# stack deploy picked up nothing at all — a footgun that also made any editor UI
# useless.
#
# The order below is the safety, not ceremony:
#   1. parse the new file in a SUBSHELL (config_field), so a syntax error, bad
#      command or stray `exit` in an edit cannot kill the process enforcing the
#      CURRENT policy;
#   2. validate it with the same 4-field grammar as boot before anything is adopted;
#   3. on failure, keep the running policy, log the reason, and record the bad md5 so
#      it is not retried every poll (a later fix changes the md5 and retries);
#   4. explicitly clear the chain of any policy that DISAPPEARED from the file —
#      otherwise it keeps enforcing rules nobody can see in the config any more.
#      Only SIGTERM/cleanup used to remove chains, and only for names still present.
reload_if_changed() {
  _md5=$(config_md5)
  [ -n "$_md5" ] || return 0
  # if/fi, not `[ ... ] && return 0`: an AND-OR list whose last command does not run
  # leaves a non-zero status, which `set -e` may act on in a future shell — and
  # exiting here would crash-loop the guard on every config change.
  if [ "$_md5" = "$CONFIG_MD5" ]; then
    return 0
  fi

  # `set +e` because load_config signals failure by RETURN CODE, and we want
  # POL_ERR for the log even when it returns 1.
  _err=$( ( set +e; load_config >/dev/null 2>&1; printf '%s' "$POL_ERR" ) )
  if [ -n "$_err" ]; then
    RELOAD_ERR="$_err"
    # Log once per distinct bad edit, not once per poll. CONFIG_MD5 is NOT advanced:
    # status.json keeps reporting the md5 that is actually programmed, which is what
    # lets a reader say "the file changed but did not take effect" instead of lying.
    if [ "$_md5" != "$REFUSED_MD5" ]; then
      log "RELOAD refused ($CONFIG): $_err — keeping the running policy"
      REFUSED_MD5="$_md5"
    fi
    # Publish the refusal immediately: the reason is the most useful thing a reader can
    # see, and status.json is where it lives (watch() rewrites it later in the cycle too).
    write_status || true
    return 0
  fi

  _prev_names=$POLICY_NAMES
  if ! load_config >/dev/null 2>&1; then
    RELOAD_ERR="unexpected failure re-reading $CONFIG"
    log "RELOAD: $RELOAD_ERR — keeping the running policy"
    return 0
  fi
  CONFIG_MD5="$_md5"
  REFUSED_MD5=""
  RELOAD_ERR=""
  GENERATION=$((GENERATION + 1))

  for _old in $_prev_names; do
    case " $POLICY_NAMES " in
      *" $_old "*) ;;
      *) log "RELOAD: policy '$_old' is gone from $CONFIG — clearing DOCKERNET_$_old"
         rm -f "/tmp/.docker-net-guard.$_old.ips" "/tmp/.docker-net-guard.$_old.state" 2>/dev/null || true
         clear_policy "DOCKERNET_$_old" "" ;;
    esac
  done

  log "RELOAD: applied $CONFIG (md5 $_md5) — $(printf '%s' "$POLICY_NAMES" | wc -w) policies, modes '$MODES'"
  build_all
}

cleanup() {
  log "clearing all policies"
  for n in $POLICY_NAMES; do
    clear_policy "DOCKERNET_$n" ""
  done
  while "$IPT" -t filter -C DOCKER-USER -j "$ROOT_CHAIN" 2>/dev/null; do
    "$IPT" -t filter -D DOCKER-USER -j "$ROOT_CHAIN" 2>/dev/null || break
  done
  if "$IPT" -t filter -L "$ROOT_CHAIN" >/dev/null 2>&1; then
    "$IPT" -t filter -F "$ROOT_CHAIN" 2>/dev/null || true
    "$IPT" -t filter -X "$ROOT_CHAIN" 2>/dev/null || true
  fi
  # CROSS-BRIDGE IS DELIBERATELY LEFT IN PLACE. It is idempotent and re-verified
  # on every poll, so keeping it hooked means a restart has no open window and a
  # stopped guard fails closed. Manual clear: see the XBRIDGE block above.
  log "cross-bridge: leaving $XBRIDGE_CHAIN hooked (fails closed; see the manual-clear note)"
  exit 0
}

trap cleanup TERM INT

log "policies: $POLICIES"
log "modes: $MODES"
build_all
watch