"""Validation and the write path, each test starting from the pristine config."""
from __future__ import annotations

import hashlib

import pytest


def md5(path) -> str:
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def model(ng):
    return ng.build_model()


def bus(ng, name: str) -> dict:
    return next(b for b in model(ng)["buses"] if b["name"] == name)


# ─── the read model ──────────────────────────────────────────────────────────
def test_model_lists_guarded_labelled_and_unguarded_networks(ng, fresh_conf):
    m = model(ng)
    found = {b["name"]: (b["mode"], b["member_count"]) for b in m["buses"]}
    assert found == {
        "edge": ("enforce", 2),      # policy, src
        "backend": ("observe", 3),   # policy, dst (web is on both networks)
        "workers": (None, 2),        # no policy, discovered from the netguard.bus label
    }
    assert "project_default" not in found       # a stack-local network is not a bus
    assert m["counts"] == {"buses": 3, "enforce": 1, "observe": 1, "open": 1}


def test_resolution_matches_membership(ng, fresh_conf):
    backend = bus(ng, "backend")
    assert {r["target"]: r["status"] for r in backend["resolved"]} == {
        "postgres": "resolved",
        "redis": "resolved",
    }
    assert backend["live"]["installed"] == "10.10.20.5:5432,10.10.20.6:6379"
    assert backend["live"]["state"] == "ok"


def test_observed_flows_come_from_the_guard(ng, fresh_conf):
    backend = bus(ng, "backend")
    assert backend["drops"]["ok"]
    assert [f["count"] for f in backend["drops"]["flows"]] == [12, 3]
    assert backend["drops"]["flows"][0]["last_wall"].count(":") == 2   # wall clock


def test_members_carry_the_name_that_will_be_written(ng, fresh_conf):
    # `db` is a purpose alias on the backend network; that is what a rule should say.
    backend = bus(ng, "backend")
    postgres = next(m for m in backend["members"] if m["name"] == "postgres")
    assert postgres["write_as"] in ("db", "postgres")


def test_each_bus_records_where_it_came_from(ng, fresh_conf):
    """The three sources are a UNION: policy (enforced), bus definitions (listed),
    docker label (listed). Nothing synchronises them — the guard only reads the
    config, so `buses.txt` and the label never change what is enforced."""
    buses = {b["name"]: b for b in model(ng)["buses"]}
    assert buses["edge"]["sources"] == ["policy", "file"]      # policy + buses.txt
    assert buses["backend"]["sources"] == ["policy", "file"]
    assert buses["workers"]["sources"] == ["file", "label"]    # definition + label


def test_a_bus_only_in_the_definitions_is_listed_and_open(ng, fresh_conf):
    workers = bus(ng, "workers")
    assert workers["policy"] is None
    assert workers["member_count"] == 2                        # discovery is live
    assert workers["warnings"][0]["kind"] == "open"


def test_a_stale_definition_is_flagged_but_harmless(ng, fresh_conf):
    path = fresh_conf.parent / "buses.txt"
    original = path.read_text(encoding="utf-8")
    try:
        path.write_text(original + "\nghost 10.99.0.0/24\n", encoding="utf-8")
        ghost = next(b for b in model(ng)["buses"] if b["name"] == "ghost")
        assert ghost["exists"] is False and ghost["member_count"] == 0
        assert [w["kind"] for w in ghost["warnings"]] == ["open", "stale-entry"]
    finally:
        path.write_text(original, encoding="utf-8")


def test_a_policy_for_a_missing_network_is_an_error_not_a_stale_entry(ng, fresh_conf):
    # A policy naming a network docker does not have matches nothing at all: that is
    # worse than a stale listing, so it is not reported as one.
    path = fresh_conf.parent / "buses.txt"
    original = path.read_text(encoding="utf-8")
    text = fresh_conf.read_text(encoding="utf-8")
    try:
        path.write_text(original + "\nghost 10.99.0.0/24\n", encoding="utf-8")
        fresh_conf.write_text(
            text.replace(
                'edge     src 10.10.10.0/24 traefik',
                'edge     src 10.10.10.0/24 traefik\nghost    dst 10.99.0.0/24 traefik',
            ),
            encoding="utf-8",
        )
        ghost = next(b for b in model(ng)["buses"] if b["name"] == "ghost")
        kinds = [w["kind"] for w in ghost["warnings"]]
        assert "missing-net" in kinds and "stale-entry" not in kinds
    finally:
        path.write_text(original, encoding="utf-8")


# ─── validation ──────────────────────────────────────────────────────────────
def test_validate_accepts_a_fan_in_rule_with_ports(ng, fresh_conf):
    entries, warnings = ng.validate_rule(
        model(ng), "workers", "servers", [{"target": "worker", "port": "8080"}], "observe"
    )
    assert entries == ["worker:8080"]
    assert warnings == []


def test_validate_accepts_a_fan_out_rule(ng, fresh_conf):
    entries, _ = ng.validate_rule(model(ng), "workers", "callers", [{"target": "worker"}], "enforce")
    assert entries == ["worker"]


def test_validate_refuses_an_unknown_app(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="not on workers"):
        ng.validate_rule(model(ng), "workers", "servers", [{"target": "nope"}], "observe")


def test_validate_refuses_ports_on_a_caller_rule(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="ports only apply"):
        ng.validate_rule(model(ng), "workers", "callers", [{"target": "worker", "port": "80"}], "observe")


def test_validate_refuses_an_empty_allowlist(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="at least one app"):
        ng.validate_rule(model(ng), "workers", "servers", [], "observe")


def test_validate_refuses_a_bad_port(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="not a TCP port"):
        ng.validate_rule(model(ng), "workers", "servers", [{"target": "worker", "port": "0"}], "observe")


def test_validate_carries_literal_addresses_through(ng, fresh_conf):
    entries, _ = ng.validate_rule(
        model(ng), "workers", "servers", [{"target": "worker"}], "observe", ["10.20.0.99:*"]
    )
    assert entries == ["10.20.0.99:*", "worker"]


def test_validate_warns_when_the_rule_covers_most_of_the_bus(ng, fresh_conf):
    _, warnings = ng.validate_rule(
        model(ng), "workers", "servers", [{"target": "worker"}, {"target": "rogue"}], "observe"
    )
    assert warnings and "most of the bus" in warnings[0]


# ─── the write path ──────────────────────────────────────────────────────────
def test_write_rule_creates_a_policy_and_backs_up(ng, fresh_conf):
    before = fresh_conf.read_text(encoding="utf-8")
    result = ng.write_rule(
        model(ng), "workers", "servers", [{"target": "worker", "port": "8080"}], "observe", md5(fresh_conf)
    )
    after = fresh_conf.read_text(encoding="utf-8")
    assert after != before
    assert "+workers" in result["diff"]
    assert ng.parse_conf_text(after)["ok"]
    parsed = ng.parse_conf_text(after)
    assert next(p for p in parsed["policies"] if p["name"] == "workers")["allow"] == "worker:8080"
    backups = list((fresh_conf.parent.parent / "data" / "backups").glob("*.bak"))
    assert backups and any(b.read_text(encoding="utf-8") == before for b in backups)


def test_write_rule_keeps_ownership_mode_and_leaves_no_temp(ng, fresh_conf):
    before = fresh_conf.stat()
    ng.write_rule(model(ng), "workers", "callers", [{"target": "rogue"}], "enforce", md5(fresh_conf))
    after = fresh_conf.stat()
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert oct(after.st_mode & 0o777) == oct(before.st_mode & 0o777)
    assert not [p for p in fresh_conf.parent.iterdir() if p.name.startswith(".docker-net-guard")]


def test_write_rule_refuses_a_stale_page(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="changed on disk"):
        ng.write_rule(model(ng), "workers", "callers", [{"target": "rogue"}], "enforce", "deadbeef")


def test_mode_flip_keeps_the_allowlist(ng, fresh_conf):
    ng.write_rule(model(ng), "workers", "callers", [{"target": "rogue"}], "observe", md5(fresh_conf))
    ng.set_rule_mode(model(ng), "workers", "enforce", md5(fresh_conf))
    parsed = ng.parse_conf_text(fresh_conf.read_text(encoding="utf-8"))
    assert next(p for p in parsed["policies"] if p["name"] == "workers")["allow"] == "rogue"
    assert "workers" not in parsed["modes"]


def test_mode_flip_refuses_a_bus_without_a_policy(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="no policy"):
        ng.set_rule_mode(model(ng), "workers", "observe", md5(fresh_conf))


def test_delete_rule_removes_policy_and_mode(ng, fresh_conf):
    ng.write_rule(model(ng), "workers", "callers", [{"target": "rogue"}], "observe", md5(fresh_conf))
    ng.delete_rule(model(ng), "workers", md5(fresh_conf))
    parsed = ng.parse_conf_text(fresh_conf.read_text(encoding="utf-8"))
    assert "workers" not in [p["name"] for p in parsed["policies"]]
    assert "workers" not in parsed["modes"]


def test_delete_rule_refuses_a_bus_without_a_policy(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="no policy to remove"):
        ng.delete_rule(model(ng), "workers", md5(fresh_conf))


def test_allow_flow_adds_the_observed_destination(ng, fresh_conf):
    flow = bus(ng, "backend")["drops"]["flows"][0]
    ng.allow_flow(model(ng), "backend", {"src": flow["src"], "dst": flow["dst"],
                                         "dport": flow["dpt"], "md5": md5(fresh_conf)})
    parsed = ng.parse_conf_text(fresh_conf.read_text(encoding="utf-8"))
    allow = next(p for p in parsed["policies"] if p["name"] == "backend")["allow"]
    assert allow.count(":5432") >= 1 and "db" in allow


def test_allow_flow_refuses_an_address_not_on_the_bus(ng, fresh_conf):
    with pytest.raises(ng.RuleError, match="no container currently sits"):
        ng.allow_flow(model(ng), "backend",
                      {"src": "10.10.20.10", "dst": "10.99.99.99", "dport": "1", "md5": md5(fresh_conf)})
