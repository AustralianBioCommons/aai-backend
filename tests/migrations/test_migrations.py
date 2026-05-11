from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlmodel import Session, create_engine

from db.models import BiocommonsGroup


def test_sbp_group_migration_creates_expected_group(tmp_path, mocker):
    db_path = tmp_path / "sbp_group_migration.sqlite"
    db_url = f"sqlite:///{db_path}"

    mocker.patch("db.setup.get_db_config", return_value=(db_url, {"check_same_thread": False}))

    repo_root = Path(__file__).resolve().parents[2]
    alembic_config = Config(str(repo_root / "alembic.ini"))

    command.upgrade(alembic_config, "98e639b5731f")

    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
    )
    try:
        with Session(engine) as session:
            group = session.get(BiocommonsGroup, "biocommons/group/sbp_workflow_execution")
            assert group is not None
            assert group.group_id == "biocommons/group/sbp_workflow_execution"
            assert group.name == "Structural Biology Platform Bundle"
            assert group.short_name == "SBP"
            assert group.is_deleted is False
    finally:
        engine.dispose()
