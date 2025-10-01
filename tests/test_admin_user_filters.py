import pytest

from routers.admin import UserQueryParams


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
