import json
import types
import pytest

import ckan_client


class _FakeResponse:
    def __init__(self, data: dict, status_code: int = 200):
        self._data = data
        self.status_code = status_code
        self.text = json.dumps(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        # Simulate httpx behavior: raise for 4xx/5xx
        if self.status_code >= 400:
            raise ckan_client.httpx.HTTPStatusError(
                "error", request=None, response=self
            )


class _FakeHttpxClientOK:
    """httpx.Client mock that returns success=true with one org."""

    def __init__(self, **kwargs):
        pass

    def post(self, url, json=None):
        # Ensure we're calling the expected CKAN action path
        assert url.endswith(ckan_client.CKANClient.ACTION_AUTOREGISTER_ORGS)
        return _FakeResponse(
            {
                "success": True,
                "result": [{"id": "1", "name": "bpa", "title": "Bioplatforms Australia"}],
            }
        )


class _FakeHttpxClientSuccessFalse:
    """httpx.Client mock that returns success=false (CKAN action error)."""

    def __init__(self, **kwargs):
        pass

    def post(self, url, json=None):
        return _FakeResponse({"success": False, "error": {"message": "boom"}})


def test_ckan_client_success(monkeypatch):
    # Replace httpx.Client with our fake
    monkeypatch.setattr(
        ckan_client, "httpx", types.SimpleNamespace(Client=_FakeHttpxClientOK)
    )
    cli = ckan_client.CKANClient(
        base_url="https://ckan.example.org",
        api_key=None,
        timeout_s=5,
        verify_ssl=True,
    )

    orgs = cli.get_autoregister_organizations()
    assert len(orgs) == 1
    assert orgs[0].id == "1"
    assert orgs[0].name == "bpa"
    assert orgs[0].title == "Bioplatforms Australia"


def test_ckan_client_success_false_raises(monkeypatch):
    monkeypatch.setattr(
        ckan_client, "httpx", types.SimpleNamespace(Client=_FakeHttpxClientSuccessFalse)
    )
    cli = ckan_client.CKANClient(
        base_url="https://ckan.example.org",
        api_key="secret",
        timeout_s=5,
        verify_ssl=True,
    )

    with pytest.raises(ValueError):
        _ = cli.get_autoregister_organizations()
