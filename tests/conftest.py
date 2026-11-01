"""Test harness: a replay of the Docker API, a scratch copy of the config, and the
app imported with that environment, so the tests exercise the real code paths."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
APP = os.path.join(ROOT, "ui", "netguard.py")
CONF = os.path.join(ROOT, "config", "docker-net-guard.conf")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("timed out waiting for %s" % url)


@pytest.fixture(scope="session")
def workdir(tmp_path_factory):
    """A throwaway copy of config/, state/ and data/ — never the repo's own files."""
    root = tmp_path_factory.mktemp("netguard")
    config = root / "config"
    config.mkdir()
    shutil.copy(CONF, config / "docker-net-guard.conf")
    shutil.copy(os.path.join(ROOT, "config", "buses.txt"), config / "buses.txt")

    state = root / "state"
    state.mkdir()
    data = root / "data"
    data.mkdir()

    # status.json exactly as the guard would publish it, with the real config md5 so
    # the "config changed on disk" warning stays silent.
    status = json.load(open(os.path.join(FIXTURES, "docker.json"), encoding="utf-8"))["status"]
    status["config"]["md5"] = hashlib.md5((config / "docker-net-guard.conf").read_bytes()).hexdigest()
    status["now"] = int(time.time())
    (state / "status.json").write_text(json.dumps(status), encoding="utf-8")

    return {
        "root": root,
        "config": config,
        "conf": config / "docker-net-guard.conf",
        "state": state,
        "data": data,
    }


@pytest.fixture(scope="session")
def docker_api():
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "tests", "serve_fixtures.py"), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    wait_http("http://127.0.0.1:%d/_ping" % port)
    yield "tcp://127.0.0.1:%d" % port
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="session")
def env(workdir, docker_api):
    values = {
        "DOCKER_HOST": docker_api,
        "GUARD_CONF": str(workdir["conf"]),
        "GUARD_STATE_DIR": str(workdir["state"]),
        "BUSES_FILE": str(workdir["config"] / "buses.txt"),
        "BACKUP_DIR": str(workdir["data"] / "backups"),
        "GUARD_CONTAINER": "netguard-guard",
        "NETGUARD_WRITE": "1",
        "STATE_TTL": "0",
    }
    old = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    yield values
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture
def fresh_conf(workdir, env):
    """Restore the pristine config before a test that writes to it."""
    shutil.copy(CONF, workdir["conf"])
    status_path = workdir["state"] / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["config"]["md5"] = hashlib.md5(workdir["conf"].read_bytes()).hexdigest()
    status["now"] = int(time.time())
    status_path.write_text(json.dumps(status), encoding="utf-8")
    return workdir["conf"]


@pytest.fixture(scope="session")
def ng(env):
    """The app, imported with the test environment already in place."""
    spec = importlib.util.spec_from_file_location("netguard_under_test", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def server(env, ng, workdir):
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-B", APP],
        env=dict(os.environ, LISTEN="127.0.0.1:%d" % port),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = "http://127.0.0.1:%d" % port
    wait_http(base + "/healthz")
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def post(url: str, payload: dict, headers: dict | None = None) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers=dict({"Content-Type": "application/json"}, **(headers or {})),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a JSON body
        return json.loads(exc.read())


def get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode()
