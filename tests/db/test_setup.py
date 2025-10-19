from db.setup import POSTGRES_CONNECT_ARGS, SQLITE_CONNECT_ARGS, get_db_config


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
