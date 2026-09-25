"""Shared pytest fixtures for the API test-suite."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    monkeypatch.setenv("BIDI_DB_PATH", tmp.name)
    # import after env is set
    from app import database
    from app.main import app
    database.DB_PATH = tmp.name
    database.init_db(tmp.name)
    with TestClient(app) as c:
        yield c
    os.unlink(tmp.name)
