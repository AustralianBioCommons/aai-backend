import pytest

from db.setup import (
    POSTGRES_CONNECT_ARGS,
    SQLITE_CONNECT_ARGS,
    create_db_and_tables,
    get_db_config,
    get_db_session,
    get_engine,
)


def test_db_config_db_host(monkeypatch):
    """
    Test we return a postgres connection URL
    when the DB_HOST environment variable is set
    (we use this on AWS, where we need to combine
    it with the DB_USER and DB_PASSWORD environment variables)
    """
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.setenv("DB_HOST", "db:5432")
    monkeypatch.setenv("DB_USER", "user")
    monkeypatch.setenv("DB_PASSWORD", "password")
    db_url, connect_args = get_db_config()
    assert "user:password@db:5432" in db_url
    assert connect_args == POSTGRES_CONNECT_ARGS


def test_db_config_db_url(monkeypatch):
    """
    Test we return the provided connection string
    when the DB_URL environment variable is set
    """
    env_url = "sqlite:///database.db"
    monkeypatch.delenv("DB_HOST", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.setenv("DB_URL", env_url)
    db_url, connect_args = get_db_config()
    assert db_url == env_url
    assert connect_args == SQLITE_CONNECT_ARGS
    assert connect_args["check_same_thread"] is False


def test_db_config_db_host_and_port(monkeypatch):
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.setenv("DB_HOST", "db")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_USER", "user")
    monkeypatch.setenv("DB_PASSWORD", "password")
    db_url, connect_args = get_db_config()
    assert "user:password@db:5432" in db_url
    assert connect_args == POSTGRES_CONNECT_ARGS


def test_db_config_db_host_preserves_existing_port(monkeypatch):
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.setenv("DB_HOST", "db.internal:6432")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_USER", "user")
    monkeypatch.setenv("DB_PASSWORD", "password")
    db_url, _ = get_db_config()
    assert "user:password@db.internal:6432" in db_url


def test_db_config_db_name_appended(monkeypatch):
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.setenv("DB_HOST", "db")
    monkeypatch.setenv("DB_USER", "user")
    monkeypatch.setenv("DB_PASSWORD", "password")
    monkeypatch.setenv("DB_NAME", "service")
    db_url, _ = get_db_config()
    assert db_url.endswith("/service")


def test_db_config_db_name_optional(monkeypatch):
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.setenv("DB_HOST", "db")
    monkeypatch.setenv("DB_USER", "user")
    monkeypatch.setenv("DB_PASSWORD", "password")
    monkeypatch.delenv("DB_NAME", raising=False)
    db_url, _ = get_db_config()
    assert not db_url.endswith("/")


def test_db_config_explicit_non_sqlite_url(monkeypatch):
    env_url = "postgresql+psycopg://user:password@db/service"
    monkeypatch.setenv("DB_URL", env_url)
    monkeypatch.delenv("DB_HOST", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    db_url, connect_args = get_db_config()
    assert db_url == env_url
    assert connect_args == POSTGRES_CONNECT_ARGS


def test_db_config_env_fallback_sqlite(monkeypatch):
    def fake_dotenv_values(_):
        return {"DB_URL": "sqlite:///local.db"}

    monkeypatch.delenv("DB_HOST", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.setattr("db.setup.dotenv_values", fake_dotenv_values)
    db_url, connect_args = get_db_config()
    assert db_url == "sqlite:///local.db"
    assert connect_args["check_same_thread"] is False


def test_db_config_env_fallback_postgres(monkeypatch):
    def fake_dotenv_values(_):
        return {"DB_URL": "postgresql+psycopg://user:password@db/service"}

    monkeypatch.delenv("DB_HOST", raising=False)
    monkeypatch.delenv("DB_NAME", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.setattr("db.setup.dotenv_values", fake_dotenv_values)
    db_url, connect_args = get_db_config()
    assert db_url == "postgresql+psycopg://user:password@db/service"
    assert connect_args == POSTGRES_CONNECT_ARGS


def test_get_engine_caches_instance(monkeypatch):
    sentinel_engine = object()
    monkeypatch.setattr("db.setup._engine", None)
    monkeypatch.setattr("db.setup.get_db_config", lambda: ("sqlite://", {}))
    create_engine_calls = []

    def fake_create_engine(*args, **kwargs):
        create_engine_calls.append((args, kwargs))
        return sentinel_engine

    monkeypatch.setattr("db.setup.create_engine", fake_create_engine)

    first = get_engine()
    second = get_engine()

    assert first is sentinel_engine
    assert second is sentinel_engine
    assert len(create_engine_calls) == 1


def test_create_db_and_tables_calls_metadata_for_sqlite(monkeypatch):
    mock_engine = object()
    monkeypatch.setattr("db.setup.get_db_config", lambda: ("sqlite:///local.db", {}))
    monkeypatch.setattr("db.setup.get_engine", lambda: mock_engine)
    created = {"called": False, "engine": None}

    def fake_create_all(engine):
        created["called"] = True
        created["engine"] = engine

    monkeypatch.setattr("db.setup.BaseModel.metadata.create_all", fake_create_all)

    create_db_and_tables()

    assert created["called"] is True
    assert created["engine"] is mock_engine


def test_create_db_and_tables_skips_non_sqlite(monkeypatch):
    monkeypatch.setattr(
        "db.setup.get_db_config",
        lambda: ("postgresql+psycopg://user:password@db/service", {}),
    )
    create_all_calls = {"count": 0}

    def fake_create_all(_):
        create_all_calls["count"] += 1

    monkeypatch.setattr("db.setup.BaseModel.metadata.create_all", fake_create_all)

    create_db_and_tables()

    assert create_all_calls["count"] == 0


def test_get_db_session_yields_and_closes(monkeypatch):
    events = []

    class FakeSession:
        def close(self):
            events.append("close")

    fake_session = FakeSession()
    engine = object()

    class FakeSessionContext:
        def __enter__(self):
            events.append("enter")
            return fake_session

        def __exit__(self, exc_type, exc, tb):
            events.append("exit")
            return False

    monkeypatch.setattr("db.setup.get_engine", lambda: engine)
    monkeypatch.setattr("db.setup.Session", lambda eng: FakeSessionContext())

    generator = get_db_session()
    yielded = next(generator)
    assert yielded is fake_session

    with pytest.raises(StopIteration):
        next(generator)

    assert events == ["enter", "close", "exit"]
