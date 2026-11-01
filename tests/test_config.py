"""Parsing and rendering the guard's shell config."""
from __future__ import annotations


def test_parses_policies_and_modes(ng, workdir):
    conf = ng.read_guard_conf()
    assert conf["ok"], conf["error"]
    names = [p["name"] for p in conf["policies"]]
    assert names == ["edge", "backend"]
    edge = conf["policies"][0]
    assert (edge["dir"], edge["subnet"], edge["allow"]) == ("src", "10.10.10.0/24", "traefik")
    assert conf["modes"] == {"backend": "observe"}


def test_unknown_modes_default_to_enforce(ng):
    conf = ng.parse_conf_text('POLICIES="x src 10.0.0.0/24 a"\nMODES=""\n')
    assert conf["ok"]
    assert conf["modes"] == {}


def test_rejects_a_broken_policy_list(ng):
    conf = ng.parse_conf_text('POLICIES="x src 10.0.0.0/24"\nMODES=""\n')
    assert not conf["ok"]
    assert "multiple of 4" in conf["error"]


def test_missing_block_is_an_error(ng):
    conf = ng.parse_conf_text('MODES=""\n')
    assert not conf["ok"]


def test_format_preserves_every_comment(ng, env):
    original = open(env["GUARD_CONF"], encoding="utf-8").read()
    parsed = ng.parse_conf_text(original)
    rendered = ng.format_conf_text(original, parsed["policies"], parsed["modes"])

    # Only the two managed regions may change; the prose that justifies the policy
    # must survive byte for byte.
    comments_before = [l for l in original.splitlines() if l.lstrip().startswith("#")]
    comments_after = [l for l in rendered.splitlines() if l.lstrip().startswith("#")]
    assert comments_before == comments_after


def test_format_is_idempotent_and_round_trips(ng, env):
    original = open(env["GUARD_CONF"], encoding="utf-8").read()
    parsed = ng.parse_conf_text(original)
    once = ng.format_conf_text(original, parsed["policies"], parsed["modes"])
    again = ng.format_conf_text(once, ng.parse_conf_text(once)["policies"], parsed["modes"])
    assert once == again


def test_format_keeps_existing_order_and_appends(ng, env):
    original = open(env["GUARD_CONF"], encoding="utf-8").read()
    parsed = ng.parse_conf_text(original)
    policies = parsed["policies"] + [
        {"name": "workers", "dir": "dst", "subnet": "10.20.0.0/24", "allow": "worker", "entries": ["worker"]}
    ]
    rendered = ng.format_conf_text(original, policies, {"backend": "observe", "workers": "observe"})
    body = rendered.split('POLICIES="', 1)[1].split('\n"', 1)[0]
    names = [line.split()[0] for line in body.strip().splitlines()]
    assert names == ["edge", "backend", "workers"]
    # the pre-existing observe entry keeps its position, the new one is appended
    modes = [l for l in rendered.splitlines() if l.startswith("MODES=")][0]
    assert modes == 'MODES="backend:observe,workers:observe"'


def test_format_refuses_a_config_it_cannot_find(ng):
    import pytest

    with pytest.raises(ng.RuleError):
        ng.format_conf_text("# nothing here\n", [], {})
