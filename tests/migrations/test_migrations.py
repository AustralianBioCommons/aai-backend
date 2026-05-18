from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
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


def test_sbp_cleanup_migration_removes_legacy_group_and_recreates_current_group(tmp_path, mocker):
    db_path = tmp_path / "sbp_cleanup_migration.sqlite"
    db_url = f"sqlite:///{db_path}"

    mocker.patch("db.setup.get_db_config", return_value=(db_url, {"check_same_thread": False}))

    repo_root = Path(__file__).resolve().parents[2]
    alembic_config = Config(str(repo_root / "alembic.ini"))

    command.upgrade(alembic_config, "274454823044")

    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
    )
    try:
        with Session(engine) as session:
            session.exec(
                text(
                    "DELETE FROM biocommonsgroup "
                    "WHERE group_id = 'biocommons/group/sbp_workflow_execution'"
                )
            )
            session.exec(
                text(
                    """
                    INSERT INTO biocommonsgroup (group_id, name, short_name, is_deleted)
                    VALUES (
                        'biocommons/group/sbp_bundle',
                        'Structural Biology Platform Bundle',
                        'SBP',
                        FALSE
                    )
                    """
                )
            )
            session.exec(
                text(
                    """
                    INSERT INTO auth0role (id, name, description, is_deleted)
                    VALUES ('legacy-sbp-admin-role', 'biocommons/role/sbp_bundle/admin', '', FALSE)
                    """
                )
            )
            session.exec(
                text(
                    """
                    INSERT INTO grouprolelink (group_id, role_id, is_deleted)
                    VALUES ('biocommons/group/sbp_bundle', 'legacy-sbp-admin-role', FALSE)
                    """
                )
            )
            session.commit()

        command.upgrade(alembic_config, "4000ecb2796d")

        with Session(engine) as session:
            legacy_group = session.get(BiocommonsGroup, "biocommons/group/sbp_bundle")
            group = session.get(BiocommonsGroup, "biocommons/group/sbp_workflow_execution")
            legacy_links = session.exec(
                text(
                    "SELECT COUNT(*) FROM grouprolelink "
                    "WHERE group_id = 'biocommons/group/sbp_bundle'"
                )
            ).one()[0]

            assert legacy_group is None
            assert legacy_links == 0
            assert group is not None
            assert group.group_id == "biocommons/group/sbp_workflow_execution"
            assert group.name == "Structural Biology Platform Bundle"
            assert group.short_name == "SBP"
            assert group.is_deleted is False
    finally:
        engine.dispose()
