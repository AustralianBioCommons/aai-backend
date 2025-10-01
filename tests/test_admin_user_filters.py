import random

import pytest

from db.models import BiocommonsUser
from db.types import PlatformEnum
from routers.admin import UserQueryParams
from tests.db.datagen import Auth0RoleFactory, BiocommonsUserFactory, PlatformFactory


def test_user_query_no_params():
    """
    Check that UserQueryParams works with no params.

    Also checks that all the required query methods
    exist, since these are checked on init.
    :return:
    """
    query = UserQueryParams()
    assert query.get_query_conditions() == []


def test_user_query_params_missing_method(monkeypatch):
    """
    Test that UserQueryParams raises an error if a query method is missing.
    """
    monkeypatch.delattr(UserQueryParams, "email_verified_query")
    with pytest.raises(NotImplementedError, match="Missing query method for field 'email_verified'"):
        UserQueryParams(email_verified=True)


def test_user_query_multiple_filters(test_client, as_admin_user, test_db_session, persistent_factories):
    """
    Test that multiple conditions can be combined correctly
    """
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    for platform in PlatformEnum:
        PlatformFactory.create_sync(id=platform.value, admin_roles=[admin_role])
    users = BiocommonsUserFactory.create_batch_sync(size=100)
    for user in users:
        random_platform = random.choice(list(PlatformEnum))
        user.add_platform_membership(
            platform=random_platform.value,
            db_session=test_db_session,
            auto_approve=random.choice([True, False])
        )
    test_db_session.flush()
    test_db_session.commit()
    resp = test_client.get("/admin/users?email_verified=true&platform=galaxy&platform_approval_status=approved&page=1&per_page=10")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    for user_record in data:
        user = test_db_session.get(BiocommonsUser, user_record["id"])
        # Generated to only have one platform membership
        platform = user.platform_memberships[0]
        assert user.email_verified
        assert platform.platform_id == PlatformEnum.GALAXY.value
        assert platform.approval_status == "approved"
