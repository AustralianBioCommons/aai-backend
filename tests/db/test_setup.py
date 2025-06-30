from db.setup import get_db_config


def test_db_config_db_host(monkeypatch):
    """
    Test we return a postgres connection URL
    when the DB_HOST environment variable is set
    (we use this on AWS, where we need to combine
    it with the DB_USER and DB_PASSWORD environment variables)
    """
    monkeypatch.setenv("DB_HOST", "db:5432")
    monkeypatch.setenv("DB_USER", "user")
    monkeypatch.setenv("DB_PASSWORD", "password")
    db_url, connect_args = get_db_config()
    assert "user:password@db:5432" in db_url
    assert connect_args == {}


def test_db_config_db_url(monkeypatch):
    """
    Test we return the provided connection string
    when the DB_URL environment variable is set
    """
    env_url = "sqlite:///database.db"
    monkeypatch.setenv("DB_URL", env_url)
    db_url, connect_args = get_db_config()
    assert db_url == env_url
    assert connect_args["check_same_thread"] is False
