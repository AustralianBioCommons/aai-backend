import os
import subprocess
import time
from contextlib import contextmanager

import click
from sqlmodel import create_engine

# --- Config ---
DB_CONTAINER_NAME = "temp_db_conn_test"
DEFAULT_POSTGRES_IMAGE = "postgres:17"
DEFAULT_PORT = 5433
POSTGRES_USER = "testuser"
POSTGRES_PASSWORD = "testpass"
POSTGRES_DB = "postgres"  # default DB created by the image

# --- Utilities ---
def run(cmd, env=None):
    print(f"> {cmd}")
    subprocess.run(cmd, shell=True, check=True, env=env or os.environ)

@contextmanager
def temp_postgres_container(port: int, image: str):
    try:
        print("🚀 Starting temporary Postgres container...")
        run(
            f"docker run --rm -d --name {DB_CONTAINER_NAME} "
            f"-e POSTGRES_USER={POSTGRES_USER} "
            f"-e POSTGRES_PASSWORD={POSTGRES_PASSWORD} "
            f"-e POSTGRES_DB={POSTGRES_DB} "
            f"-p {port}:5432 {image}"
        )
        yield
    finally:
        print("🧹 Cleaning up: stopping container...")
        subprocess.run(f"docker stop {DB_CONTAINER_NAME}", shell=True)

def wait_for_db_ready(host: str, port: int, timeout_s: int = 30):
    """
    Light wait loop that tries TCP connect via psql (if available) or sleeps briefly.
    We keep it simple to avoid adding dependencies.
    """
    start = time.time()
    while time.time() - start < timeout_s:
        # If psql is available, use it to check readiness; otherwise just sleep a bit.
        try:
            subprocess.run(
                f'psql "host={host} port={port} user={POSTGRES_USER} dbname={POSTGRES_DB}" -c "SELECT 1;"',
                shell=True,
                check=True,
                env={**os.environ, "PGPASSWORD": POSTGRES_PASSWORD},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Database did not become ready in time.")

def test_select_via_get_db_config():
    """
    Imports your project's get_db_config(), creates an engine, and runs SELECT 1.
    NOTE: Adjust the import below to where your get_db_config() lives.
    """
    # >>> CHANGE THIS IMPORT PATH IF NEEDED <<<
    # For example, if your function is in `db/config.py`, use:
    #   from db.config import get_db_config
    from db.setup import get_db_config  # <-- adjust to your module

    db_url, connect_args = get_db_config()
    print(f"🔗 DB URL: {db_url}")
    print(f"⚙️  Connect args: {connect_args}")

    engine = create_engine(db_url, connect_args=connect_args)
    with engine.connect() as conn:
        value = conn.exec_driver_sql("SELECT 1;").scalar()
        assert value == 1, f"Expected 1, got {value}"

        # Optional: check timeout settings (if Postgres)
        if db_url.startswith("postgresql"):
            timeout = conn.exec_driver_sql("SHOW statement_timeout;").scalar()
            print(f"⏱️  statement_timeout: {timeout}")

            idle_timeout = conn.exec_driver_sql(
                "SHOW idle_in_transaction_session_timeout;"
            ).scalar()
            print(f"💤 idle_in_transaction_session_timeout: {idle_timeout}")
    print("✅ Connection successful — SELECT 1 returned 1.")

@click.command()
@click.option("--port", default=DEFAULT_PORT, show_default=True, help="Host port to bind Postgres on.")
@click.option("--image", default=DEFAULT_POSTGRES_IMAGE, show_default=True, help="Postgres Docker image.")
def main(port, image):
    # Prepare env vars that your get_db_config() consumes (AWS-style branch).
    # get_db_config() will detect "host:port" and avoid adding a duplicate port.
    os.environ["DB_HOST"] = f"localhost:{port}"
    os.environ["DB_USER"] = POSTGRES_USER
    os.environ["DB_PASSWORD"] = POSTGRES_PASSWORD
    os.environ["DB_NAME"] = POSTGRES_DB  # ensure path component is present

    with temp_postgres_container(port, image):
        print("⏳ Waiting for database to be ready...")
        wait_for_db_ready("localhost", port)
        print("🧪 Running connectivity test via get_db_config()...")
        test_select_via_get_db_config()

if __name__ == "__main__":
    main()
