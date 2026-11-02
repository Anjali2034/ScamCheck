import pytest

from scamcheck import config, quota
from scamcheck.tools import history


@pytest.fixture(autouse=True)
def own_database(monkeypatch, tmp_path):
    """Every test gets an empty history and empty budgets, so tests never touch runtime/scamcheck.db or each other."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "scamcheck.db")
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "scamcheck.db")
    monkeypatch.setattr(quota, "_ai_paused_until", 0.0)
    monkeypatch.setattr(quota, "_windows", {})
