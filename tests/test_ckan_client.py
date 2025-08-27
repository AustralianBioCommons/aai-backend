import types
from typing import Any, Dict, List, Optional

import httpx
import pytest

from services.ckan_client import CKANClient, get_ckan_client


class _DummyResponse:
    def __init__(self, *, status_code: int = 200, json_payload: Any = None, request: Optional[httpx.Request] = None):
        self.status_code = status_code
        self._json = json_payload
        # httpx.HTTPStatusError needs both request and response objects
        self.request = request or httpx.Request("POST", "https://example.org")
        self.headers = {}

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code} error",
                request=self.request,
                response=httpx.Response(self.status_code, request=self.request),
            )


class _DummyHttpxClient:
    """
    Minimal sync httpx.Client stand-in that captures requests and returns a queued response.
    """
    def __init__(self, *, headers: Optional[Dict[str, str]] = None, timeout: float = 10, verify: bool = True):
        self.headers = headers or {}
        self.timeout = timeout
        self.verify = verify
        self.calls: List[Dict[str, Any]] = []
        # Response to return; test will set this per-call
        self.next_response: Optional[_DummyResponse] = None

    def post(self, url: str, json: Any = None):
        self.calls.append({"method": "POST", "url": url, "json": json, "headers": dict(self.headers)})
        if self.next_response is None:
            return _DummyResponse(json_payload={"success": True, "result": []})
        return self.next_response


@pytest.fixture
def dummy_client(monkeypatch):
    """
    Monkeypatch httpx.Client used inside CKANClient to our dummy version.
    Exposes the created dummy via closure so tests can control responses & inspect calls.
    """ 
    created: Dict[str, _DummyHttpxClient] = {}

    def _factory(*, headers=None, timeout=None, verify=None, **_):
        client = _DummyHttpxClient(headers=headers, timeout=timeout, verify=verify)
        created["client"] = client
        return client

    monkeypatch.setattr("services.ckan_client.httpx.Client", _factory)
    return created


@pytest.fixture
def stub_orgout(monkeypatch):
    """
    Replace the imported OrgOut symbol inside the module under test with a permissive stub
    so tests don't depend on the exact pydantic schema fields.
    """
    class _StubOrgOut:
        def __init__(self, **data):
            # store raw data for easy assertions if needed
            self._data = data

    monkeypatch.setattr("services.ckan_client.OrgOut", _StubOrgOut)
    return _StubOrgOut


def test_get_autoregister_organizations_success(dummy_client, stub_orgout):
    client = CKANClient(base_url="https://ckan.example/api", api_key="abc123", timeout_s=5, verify_ssl=False)

    # Arrange dummy response
    payload = {
        "success": True,
        "result": [
            {"id": "org-1", "name": "Org One", "title": "Org One"},
            {"id": "org-2", "name": "Org Two", "title": "Org Two"},
        ],
    }
    dummy_client["client"].next_response = _DummyResponse(json_payload=payload)

    # Act
    orgs = client.get_autoregister_organizations()

    # Assert: returned list length & type creation via stub
    assert len(orgs) == 2
    assert all(isinstance(o, stub_orgout) for o in orgs)

    # Assert: correct URL and Authorization header, empty JSON body per implementation
    call = dummy_client["client"].calls[-1]
    assert call["method"] == "POST"
    # ACTION path is appended to base_url (base_url rstrip('/') in __init__)
    assert call["url"].endswith("/api/3/action/ytp_request_autoregister_organization_list")
    assert call["json"] == {}
    assert call["headers"].get("Authorization") == "abc123"
    # verify & timeout wired to httpx.Client
    assert dummy_client["client"].verify is False
    assert dummy_client["client"].timeout == 5


def test_get_autoregister_organizations_empty_result(dummy_client, stub_orgout):
    client = CKANClient(base_url="https://ckan.example/", api_key=None, timeout_s=10, verify_ssl=True)

    # No api_key => no Authorization header
    dummy_client["client"].next_response = _DummyResponse(json_payload={"success": True, "result": []})
    orgs = client.get_autoregister_organizations()
    assert orgs == []

    call = dummy_client["client"].calls[-1]
    assert "Authorization" not in call["headers"]


def test_get_autoregister_organizations_http_error_raises(dummy_client, stub_orgout):
    client = CKANClient(base_url="https://ckan.example", api_key=None, timeout_s=10, verify_ssl=True)
    dummy_client["client"].next_response = _DummyResponse(status_code=502, json_payload={"success": False})

    with pytest.raises(httpx.HTTPStatusError):
        client.get_autoregister_organizations()


def test_get_autoregister_organizations_success_false_raises(dummy_client, stub_orgout):
    client = CKANClient(base_url="https://ckan.example", api_key=None, timeout_s=10, verify_ssl=True)
    dummy_client["client"].next_response = _DummyResponse(json_payload={"success": False, "error": {"message": "boom"}})

    with pytest.raises(ValueError):
        client.get_autoregister_organizations()


def test_get_ckan_client_dependency_wiring(monkeypatch):
    """
    Call get_ckan_client with an explicit Settings instance and verify fields are wired through.
    """
    # Build a tiny fake Settings object with the fields the dependency expects
    FakeSettings = types.SimpleNamespace
    settings = FakeSettings(
        ckan_base_url="https://ckan.example/",
        ckan_api_key="sekret",
        ckan_verify_ssl=True,
    )

    # Monkeypatch httpx.Client so we can inspect constructed client properties
    captured = {}

    def _factory(*, headers=None, timeout=None, verify=None, **_):
        captured["headers"] = headers or {}
        captured["timeout"] = timeout
        captured["verify"] = verify
        # return a harmless dummy that won't be used in this test
        return _DummyHttpxClient(headers=headers, timeout=timeout, verify=verify)

    monkeypatch.setattr("services.ckan_client.httpx.Client", _factory)

    # Act
    ckan_client = get_ckan_client(settings=settings)

    # Assert: constructed CKANClient has a trimmed base_url and httpx client configured
    assert isinstance(ckan_client, CKANClient)
    assert ckan_client.base_url == "https://ckan.example"  # rstrip("/")
    assert captured["headers"].get("Authorization") == "sekret"
    assert captured["timeout"] == 10  # hardcoded in dependency
    assert captured["verify"] is True
