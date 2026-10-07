"""Every test runs against disposable state and an in-memory credential store."""
import ipaddress
import socket

import pytest

import omnidim_ui
from omnidim_ui import config, security


class MemoryKeyring:
    def __init__(self):
        self.values = {}

    def get_password(self, service, user):
        return self.values.get((service, user))

    def set_password(self, service, user, password):
        self.values[(service, user)] = password

    def delete_password(self, service, user):
        self.values.pop((service, user), None)


@pytest.fixture(autouse=True)
def isolated_local_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "state.sqlite3")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(omnidim_ui, "DATA_DIR", tmp_path)
    monkeypatch.setattr(omnidim_ui, "DB_PATH", config.DB_PATH)
    monkeypatch.setattr(config, "READ_ONLY_MODE", False)
    monkeypatch.setattr(omnidim_ui, "READ_ONLY_MODE", False)
    monkeypatch.setattr(security, "IS_WINDOWS", False)
    monkeypatch.setattr(omnidim_ui, "IS_WINDOWS", False)
    monkeypatch.setattr(security, "keyring", MemoryKeyring())
    monkeypatch.delenv("OMNIDIM_API_KEY", raising=False)
    with security.TOKEN_LOCK:
        security.CONFIRMATION_TOKENS.clear()
    omnidim_ui.init_db()
    original_connect = socket.create_connection

    def local_only(address, *args, **kwargs):
        host = address[0]
        if host != "localhost":
            try:
                allowed = ipaddress.ip_address(host).is_loopback
            except ValueError:
                allowed = False
            if not allowed:
                raise AssertionError("Tests must inject a transport instead of using external networking")
        return original_connect(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", local_only)
    yield
    with security.TOKEN_LOCK:
        security.CONFIRMATION_TOKENS.clear()
