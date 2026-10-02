import pytest

# Cheap Argon2 params so the test suite stays fast. Real vaults use crypto.DEFAULT_KDF.
FAST_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost": 1024, "parallelism": 1}

MASTER = "correct horse battery staple"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.json"


@pytest.fixture(autouse=True)
def isolated_guard_store(tmp_path, monkeypatch):
    """Keep tests from writing lockout counters into the real ~/.termvault/attempts.json."""
    store = tmp_path / "attempts.json"
    monkeypatch.setattr("termvault.guard.default_store_path", lambda: store)
    return store
