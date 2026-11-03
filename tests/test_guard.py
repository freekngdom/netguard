"""The guard script, run against fake iptables/ip/docker/dmesg.

This is the highest-value test in the repo: the guard programs a host firewall, so its
logic (policy refusal, chain clearing on reload, and the ring-buffer parse) is checked
without root and without touching a real ruleset.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "guard")
GUARD = os.path.join(os.path.dirname(HERE), "guard", "docker-net-guard.sh")

# The guard resolves its tools with `command -v`; the test build points them at the
# fakes instead, and removes the blocking poll loop so the script can be sourced.
SUBS = [
    (r'^IPT="\$\(command -v iptables \|\| true\)"', 'IPT="$FAKE_IPT"'),
    (r'^DOCKER="\$\(command -v docker \|\| true\)"', 'DOCKER="$FAKE_DOCKER"'),
    (r'^IPBIN="\$\(command -v ip \|\| true\)"', 'IPBIN="$FAKE_IP"'),
    (r'^DMESG="\$\(command -v dmesg \|\| true\)"', 'DMESG="$FAKE_DMESG"'),
    (r"^watch$", "# watch loop removed for the test"),
]

CONF_TWO = (
    'POLICIES="\n'
    "edge     src 10.10.10.0/24 traefik\n"
    "backend  dst 10.10.20.0/24 postgres:5432,redis:6379\n"
    '"\nMODES="backend:observe"\nPOLL_INTERVAL=60\n'
)
CONF_PLUS = (
    'POLICIES="\n'
    "edge     src 10.10.10.0/24 traefik\n"
    "workers  dst 10.20.0.0/24 worker\n"
    '"\nMODES=""\nPOLL_INTERVAL=60\n'
)
CONF_MINUS = 'POLICIES="\nedge     src 10.10.10.0/24 traefik\n"\nMODES=""\nPOLL_INTERVAL=60\n'


def sandbox(tmp_path, conf_name="guard.conf"):
    root = tmp_path
    shutil.copy(GUARD, root / "guard.sh")
    for name in ("fake-iptables.sh", "fake-ip.sh", "fake-docker.sh", conf_name):
        shutil.copy(os.path.join(FIX, name), root / name)
        os.chmod(root / name, 0o755)
    # a fake `dmesg` that prints the captured log lines
    (root / "dmesg.sh").write_text(
        "#!/bin/sh\ncat %s\n" % os.path.join(FIX, "dmesg.txt"), encoding="utf-8"
    )
    os.chmod(root / "dmesg.sh", 0o755)

    patched = (root / "guard.sh").read_text(encoding="utf-8")
    for pattern, replacement in SUBS:
        patched, n = re.subn(pattern, replacement, patched, flags=re.M)
        assert n == 1, pattern
    (root / "guard.sh").write_text(patched, encoding="utf-8")
    (root / "state").mkdir(exist_ok=True)
    return root


def guard_env(root, conf_name="guard.conf", dmesg="dmesg.sh", path=None):
    return {
        "PATH": path or os.environ.get("PATH", "/usr/bin:/bin"),
        "FAKE_STATE": str(root / "fakestate"),
        "FAKE_IPT": str(root / "fake-iptables.sh"),
        "FAKE_IP": str(root / "fake-ip.sh"),
        "FAKE_DOCKER": str(root / "fake-docker.sh"),
        "FAKE_DMESG": str(root / dmesg),
        "GUARD_STATE_DIR": str(root / "state"),
        "GUARD_CONFIG": str(root / conf_name),
    }


def shell(root, script: str, **kw):
    return subprocess.run(
        ["sh", "-c", script], cwd=root, env=guard_env(root, **kw),
        capture_output=True, text=True, timeout=60,
    )


def boot(root, **kw):
    """Source the (patched) guard: load config, program chains, publish status."""
    return shell(root, ". ./guard.sh", **kw)


def status(root) -> dict:
    return json.loads((root / "state" / "status.json").read_text(encoding="utf-8"))


def test_guard_script_parses():
    subprocess.run(["sh", "-n", GUARD], check=True)


def test_boot_programs_policies_and_publishes_status(tmp_path):
    root = sandbox(tmp_path)
    result = boot(root)
    assert result.returncode == 0, result.stdout + result.stderr

    data = status(root)
    assert [p["name"] for p in data["policies"]] == ["edge", "backend"]
    assert {p["name"]: p["mode"] for p in data["policies"]} == {"edge": "enforce", "backend": "observe"}
    assert all(p["state"] == "ok" and p["hooked"] for p in data["policies"])
    # the allowlist is resolved through the (fake) docker API
    assert [p["installed"] for p in data["policies"]] == ["10.10.10.5", "10.10.20.5:5432,10.10.20.6:6379"]
    # two br-* bridges plus docker0: the fixture's docker0 is the regression case
    # (a `^br-` match alone left that whole /16 reachable from every other bridge).
    assert data["xbridge"]["hooked"] is True
    assert data["xbridge"]["bridges"] == 3
    assert data["xbridge"]["rules"] == 3 * 3 + 1
    assert "DOCKERNET_edge" in data["docker_user"] and "DOCKERNET_backend" in data["docker_user"]


def test_same_subnet_return_precedes_the_interface_drop(tmp_path):
    """The regression guard for the 2026-11-03 outage.

    Rule 2 ("-d <subnet> ! -i <bridge> -j DROP") is the only cross-bridge rule
    that names an interface, and a bridge name does not survive a recreate: after
    a full down/up every network returns on the same subnet with a new br-<id>.
    With the guard down, nothing re-derives the rules, so that stale interface
    name dropped same-bridge traffic -- forgejo could not reach its own database
    and its ORM gave up with "connection timed out".

    A same-subnet RETURN ahead of the DROP makes that harmles: it needs no
    interface. Ordering is the whole fix, so assert the order, not just presence.
    """
    root = sandbox(tmp_path)
    result = boot(root)
    assert result.returncode == 0, result.stdout + result.stderr

    lines = [
        ln for ln in (root / "fakestate" / "chains").read_text(encoding="utf-8").splitlines()
        if ln.startswith("rule:DOCKERNET_XBRIDGE|")
    ]

    def index(needle):
        for i, ln in enumerate(lines):
            if needle in ln:
                return i
        raise AssertionError("%r missing from %r" % (needle, lines))

    # Every docker subnet: the RETURN must come first, the interface DROP after it.
    # Specs carry the bridge's host address (10.10.10.1/24) -- iptables masks it
    # back to the network, the recorded rule does not.
    for cidr in ("10.10.10.1/24", "10.10.20.1/24", "172.17.0.1/16"):
        ret = index("-s %s -d %s" % (cidr, cidr))
        drop = index("-d %s ! -i" % cidr)
        assert ret < drop, "same-subnet RETURN for %s must precede its DROP" % cidr

    # the RETURN must be a RETURN: a same-subnet DROP would cut every bridge off
    ret_line = [ln for ln in lines if "-s 10.10.10.1/24 -d 10.10.10.1/24" in ln][0]
    assert "-j RETURN" in ret_line
    # and it must not name an interface -- that is what goes stale
    assert "-i " not in ret_line.split("-j")[0]


def test_observed_flows_are_parsed_from_the_ring_buffer(tmp_path):
    root = sandbox(tmp_path)
    boot(root)
    observed = status(root)["observed"]
    assert observed["ok"], observed["error"]
    assert observed["boot_at"] > 0
    flows = {(f["bus"], f["src"], f["dst"], f["dport"]): f["count"] for f in observed["flows"]}
    # two packets on backend:5432, one on the colon-bearing short-name shape for edge
    assert flows[("backend", "10.10.20.10", "10.10.20.5", "5432")] == 2
    assert flows[("edge", "10.10.10.10", "10.10.10.9", "8080")] == 1
    # unrelated kernel lines are ignored and no bus name keeps a truncated prefix
    assert len(observed["flows"]) == 2
    assert all(f["bus"] == f["bus"].strip() for f in observed["flows"])
    assert all(f["proto"] == "TCP" for f in observed["flows"])


def test_observed_reports_a_missing_capability_instead_of_zero(tmp_path):
    root = sandbox(tmp_path)
    boot(root, dmesg="/bin/false")
    observed = status(root)["observed"]
    assert observed["ok"] is False
    assert "dmesg failed" in observed["error"]
    assert observed["flows"] == []


def test_observed_reports_a_dmesg_that_cannot_run(tmp_path):
    root = sandbox(tmp_path)
    boot(root, dmesg="/nonexistent/dmesg")
    observed = status(root)["observed"]
    assert observed["ok"] is False and observed["flows"] == []


def test_an_unresolvable_allowlist_is_refused_not_installed(tmp_path):
    root = sandbox(tmp_path, conf_name="unresolved.conf")
    result = boot(root, conf_name="unresolved.conf")
    assert result.returncode == 0, result.stderr           # per-policy, not fatal
    assert "refusing to install" in result.stdout
    policy = status(root)["policies"][0]
    assert policy["state"] == "refused"
    assert policy["rules"] == 0
    assert "jump:DOCKERNET_edge" not in (root / "fakestate" / "chains").read_text()


def test_an_invalid_policy_list_refuses_to_start(tmp_path):
    root = sandbox(tmp_path, conf_name="broken.conf")
    result = boot(root, conf_name="broken.conf")
    assert result.returncode != 0
    assert "FATAL" in result.stdout
    assert "expected 4 fields" in result.stdout


def test_reload_adds_then_removes_a_policy_without_a_restart(tmp_path):
    root = sandbox(tmp_path)
    (root / "guard.conf").write_text(CONF_TWO, encoding="utf-8")
    driver = """\
. ./guard.sh >/dev/null 2>&1
cat > "$GUARD_CONFIG" <<'CONF'
%sCONF
reload_if_changed >/dev/null 2>&1; echo after-add=$GENERATION
cat > "$GUARD_CONFIG" <<'CONF'
%sCONF
reload_if_changed >/dev/null 2>&1; echo after-remove=$GENERATION
""" % (CONF_PLUS, CONF_MINUS)
    out = shell(root, driver)
    assert "after-add=1" in out.stdout and "after-remove=2" in out.stdout, out.stdout + out.stderr

    chains = (root / "fakestate" / "chains").read_text(encoding="utf-8")
    assert "jump:DOCKERNET_workers" not in chains        # unhooked
    assert "\nDOCKERNET_workers\n" not in chains         # and the chain is deleted
    assert "jump:DOCKERNET_edge" in chains               # the untouched policy survives


def test_a_bad_edit_is_refused_and_the_running_policy_kept(tmp_path):
    root = sandbox(tmp_path)
    (root / "guard.conf").write_text(CONF_TWO, encoding="utf-8")
    driver = """\
. ./guard.sh >/dev/null 2>&1
cat > "$GUARD_CONFIG" <<'CONF'
POLICIES="
edge src 10.10.10.0/24
"
MODES=""
CONF
reload_if_changed 2>&1 | grep -c 'RELOAD refused'
echo policies=$(printf '%s' "$POLICY_NAMES" | wc -w)
"""
    out = shell(root, driver)
    lines = out.stdout.strip().splitlines()
    assert lines[0] == "1"                 # exactly one refusal logged
    assert lines[-1].strip() == "policies=2"
    assert "jump:DOCKERNET_edge" in (root / "fakestate" / "chains").read_text(encoding="utf-8")
