"""Shared fixtures: run the app against a throwaway data/storage dir."""
import importlib
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """Import `server` and repoint its paths at a temp dir."""
    server = importlib.import_module("server")

    data = tmp_path / "data"
    storage = tmp_path / "storage"
    tmp = tmp_path / "tmp"
    for d in (data, storage, tmp):
        d.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(server, "DATA", data, raising=False)
    monkeypatch.setattr(server, "STORAGE", storage, raising=False)
    monkeypatch.setattr(server, "TMP", tmp, raising=False)
    monkeypatch.setattr(server, "SHARES_FILE", data / "shares.json", raising=False)
    monkeypatch.setattr(server, "PASSWORD_FILE", tmp_path / ".admin-password", raising=False)
    monkeypatch.setattr(server, "TOTP_FILE", tmp_path / ".admin-2fa", raising=False)
    monkeypatch.setattr(server, "SESSION_FILE", data / "sessions.json", raising=False)
    monkeypatch.setattr(server, "TOKEN", "test-token", raising=False)
    return server


@pytest.fixture()
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app.app) as c:
        yield c


@pytest.fixture()
def auth():
    return {"X-Token": "test-token"}
