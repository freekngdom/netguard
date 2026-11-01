"""The HTTP surface, including the write endpoints and their guards."""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from conftest import get, post


def md5(path) -> str:
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def test_index_lists_the_buses(server, fresh_conf):
    body = get(server + "/")
    assert "net-guard" in body
    assert "workers" in body and "OPEN" in body or "open" in body
    assert "netguard v" in body


def test_state_json_is_stable(server, fresh_conf):
    state = json.loads(get(server + "/api/state"))
    assert state["version"]
    assert state["counts"] == {"buses": 3, "enforce": 1, "observe": 1, "open": 1}
    assert state["guard"]["state"] == "up"
    assert state["conf"]["ok"]


def test_bus_page_shows_the_observed_flows(server, fresh_conf):
    body = get(server + "/bus/backend")
    assert "Observed would-be-drops" in body
    assert "10.10.20.10" in body
    assert "data-allow-flow" in body           # editing enabled -> shortcut present


def test_edit_page_renders_the_picker(server, fresh_conf):
    body = get(server + "/bus/workers/edit")
    assert 'name="shape"' in body and 'name="mode"' in body
    assert 'class="prow"' in body
    assert 'id="ng-data"' in body
    assert "/app.js" in body


def test_app_js_is_served_as_javascript(server, fresh_conf):
    with urllib.request.urlopen(server + "/app.js", timeout=10) as resp:
        assert resp.headers["Content-Type"].startswith("application/javascript")
        assert "Content-Security-Policy" in resp.headers


def test_security_headers(server, fresh_conf):
    with urllib.request.urlopen(server + "/", timeout=10) as resp:
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "default-src 'none'" in csp
        assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_create_a_rule_and_show_the_diff(server, fresh_conf):
    result = post(server + "/api/rules", {
        "bus": "workers", "shape": "servers", "mode": "observe", "md5": md5(fresh_conf),
        "allow": [{"target": "worker", "port": "8080"}],
    })
    assert result["ok"], result
    assert result["redirect"] == "/bus/workers?saved=1"

    saved = get(server + result["redirect"])
    assert "diff" in saved and "+workers" in saved
    parsed = json.loads(get(server + "/api/state"))
    assert [(b["name"], b["mode"]) for b in parsed["buses"] if b["name"] == "workers"] == [("workers", "observe")]


def test_mode_endpoint(server, fresh_conf):
    assert post(server + "/api/rules/edge/mode", {"mode": "observe", "md5": md5(fresh_conf)})["ok"]
    parsed = json.loads(get(server + "/api/state"))
    assert next(b for b in parsed["buses"] if b["name"] == "edge")["mode"] == "observe"


def test_delete_endpoint(server, fresh_conf):
    assert post(server + "/api/rules", {
        "bus": "workers", "shape": "callers", "mode": "enforce", "md5": md5(fresh_conf),
        "allow": [{"target": "rogue"}],
    })["ok"]
    assert post(server + "/api/rules/workers/delete", {"md5": md5(fresh_conf)})["ok"]
    parsed = json.loads(get(server + "/api/state"))
    assert next(b for b in parsed["buses"] if b["name"] == "workers")["mode"] is None


def test_unknown_bus_is_404(server, fresh_conf):
    with urllib.request.urlopen(server + "/api/state", timeout=10):
        pass
    try:
        urllib.request.urlopen(server + "/bus/nope", timeout=10)
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404


def test_refusals(server, fresh_conf):
    # a wrong content type is refused before anything else happens
    req = urllib.request.Request(
        server + "/api/rules", data=b"bus=workers",
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("expected a refusal")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        assert "application/json" in json.loads(exc.read())["error"]

    # a cross-origin POST is refused even with a valid body
    assert "cross-origin" in post(
        server + "/api/rules",
        {"bus": "workers", "shape": "servers", "mode": "observe", "md5": md5(fresh_conf),
         "allow": [{"target": "worker"}]},
        headers={"Origin": "https://evil.example"},
    )["error"]

    # a stale page cannot overwrite a newer config
    assert "changed on disk" in post(
        server + "/api/rules",
        {"bus": "workers", "shape": "servers", "mode": "observe", "md5": "deadbeef",
         "allow": [{"target": "worker"}]},
    )["error"]


def test_widget_payload_is_flat(server, fresh_conf):
    widget = json.loads(get(server + "/api/widget"))
    assert set(widget) == {"guard", "buses", "issues", "drops", "xbridge", "updated"}
    assert all(isinstance(v, (str, int)) for v in widget.values())
