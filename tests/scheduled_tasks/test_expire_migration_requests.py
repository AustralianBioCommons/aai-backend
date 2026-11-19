from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time
from sqlalchemy import event
from sqlmodel import Session

from db.models import AccountMigrationRequest
from scheduled_tasks.tasks import expire_account_migration_requests_job
from schemas.aaf_migration import MigrationDirection, MigrationStatus
from tests.db.datagen import BiocommonsUserFactory


@pytest.mark.parametrize("direction", list(MigrationDirection))
@freeze_time("2026-10-29 00:00:00")
def test_expire_migration_requests_uses_single_update(
    direction, test_db_engine, session, persistent_factories, monkeypatch
):
    now = datetime.now(timezone.utc)
    expected_statuses = {}
    for status, expires_delta, expected_status in (
        (MigrationStatus.PENDING, -1, MigrationStatus.EXPIRED),
        (MigrationStatus.PENDING, 0, MigrationStatus.EXPIRED),
        (MigrationStatus.PENDING, 1, MigrationStatus.PENDING),
        (MigrationStatus.COMPLETED, -1, MigrationStatus.COMPLETED),
        (MigrationStatus.EXPIRED, -1, MigrationStatus.EXPIRED),
    ):
        user = BiocommonsUserFactory.create_sync()
        request = AccountMigrationRequest(
            user_id=user.id,
            new_email="new@example.com",
            direction=direction,
            status=status,
            expires_at=now + timedelta(seconds=expires_delta),
        )
        expected_statuses[request.id] = expected_status
        session.add(request)
    session.commit()

    def get_db_session_override():
        with Session(test_db_engine) as job_session:
            yield job_session

    monkeypatch.setattr("scheduled_tasks.tasks.get_db_session", get_db_session_override)
    statements = []

    def capture_statement(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(test_db_engine, "before_cursor_execute", capture_statement)
    try:
        expire_account_migration_requests_job()
    finally:
        event.remove(test_db_engine, "before_cursor_execute", capture_statement)

    assert len(statements) == 1
    assert statements[0].lstrip().upper().startswith("UPDATE ")
    with Session(test_db_engine) as fresh_session:
        for request_id, expected_status in expected_statuses.items():
            request = fresh_session.get(AccountMigrationRequest, request_id)
            assert request.status == expected_status
            assert request.direction == direction

    # Repeating the job must leave the same records and statuses in place.
    expire_account_migration_requests_job()
    with Session(test_db_engine) as fresh_session:
        for request_id, expected_status in expected_statuses.items():
            assert fresh_session.get(AccountMigrationRequest, request_id).status == expected_status
