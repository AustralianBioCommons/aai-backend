import respx
from httpx import Response

def test_fetch_orgs_success(client_with_settings_override):
    """
    Test fetching orgs successfully from the BioPlatforms CKAN API.
    """
    dummy_orgs = ["org-one", "org-two", "org-three"]

    with respx.mock:
        respx.get("https://data.bioplatforms.com/api/3/action/organization_list").mock(
            return_value=Response(200, json={"success": True, "result": dummy_orgs})
        )

        resp = client_with_settings_override.get("/external/bioplatforms/orgs?api_key=fakekey")
        assert resp.status_code == 200
        assert resp.json() == dummy_orgs


def test_fetch_orgs_ckan_failure(client_with_settings_override):
    """
    Test CKAN API returns success=False, should be handled as 502.
    """
    with respx.mock:
        respx.get("https://data.bioplatforms.com/api/3/action/organization_list").mock(
            return_value=Response(200, json={"success": False})
        )

        resp = client_with_settings_override.get("/external/bioplatforms/orgs?api_key=fakekey")
        assert resp.status_code == 502
        assert "CKAN API call failed" in resp.text


def test_fetch_orgs_http_error(client_with_settings_override):
    """
    Test CKAN API returns an HTTP error (e.g. 403 Unauthorized).
    """
    with respx.mock:
        respx.get("https://data.bioplatforms.com/api/3/action/organization_list").mock(
            return_value=Response(403, json={"error": "Unauthorized"})
        )

        resp = client_with_settings_override.get("/external/bioplatforms/orgs?api_key=badkey")
        assert resp.status_code == 500
        assert "403 Forbidden" in resp.text
