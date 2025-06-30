from datetime import datetime, timezone

from mimesis import Person
from mimesis.locales import Locale

from db.models import GroupMembership
from tests.datagen import random_auth0_id


def test_create_group_membership(session):
    user = Person(locale=Locale("en"))
    user_id = random_auth0_id()
    updater = Person(locale=Locale("en"))
    updater_id = random_auth0_id()
    group = GroupMembership(
        group="tsi",
        user_id=user_id,
        user_email=user.email(),
        approval_status="pending",
        updated_at=datetime.now(tz=timezone.utc),
        updated_by_id=updater_id,
        updated_by_email=updater.email(),
    )
    session.add(group)
    session.commit()
    session.refresh(group)
    assert group.group == "tsi"
