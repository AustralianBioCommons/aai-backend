from unittest.mock import AsyncMock

import pytest

from register.utils import check_sbp_email_allowed
from schemas.biocommons_register import BundleRequest


@pytest.mark.asyncio
async def test_check_sbp_email_allowed_skips_check_without_bundles(mocker):
    institution_check = mocker.patch(
        "register.utils.is_australian_research_institution_email",
        new=AsyncMock(return_value=False),
    )

    assert await check_sbp_email_allowed(email="no.bundle@example.com", bundles=None) is None
    institution_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_sbp_email_allowed_skips_check_without_sbp_bundle(mocker):
    institution_check = mocker.patch(
        "register.utils.is_australian_research_institution_email",
        new=AsyncMock(return_value=False),
    )
    bundles = [BundleRequest(bundle_id="tsi", reason="TSI access")]

    assert await check_sbp_email_allowed(email="tsi.user@example.com", bundles=bundles) is None
    institution_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_sbp_email_allowed_checks_sbp_bundle(mocker):
    institution_check = mocker.patch(
        "register.utils.is_australian_research_institution_email",
        new=AsyncMock(return_value=True),
    )
    bundles = [BundleRequest(bundle_id="sbp_workflow_execution", reason="SBP access")]

    result = await check_sbp_email_allowed(email="sbp.user@unimelb.edu.au", bundles=bundles)

    assert result is None
    institution_check.assert_awaited_once_with("sbp.user@unimelb.edu.au")


@pytest.mark.asyncio
async def test_check_sbp_email_allowed_returns_error_when_domain_check_fails(mocker):
    institution_check = mocker.patch(
        "register.utils.is_australian_research_institution_email",
        new=AsyncMock(return_value=False),
    )
    bundles = [
        BundleRequest(bundle_id="tsi", reason="TSI access"),
        BundleRequest(bundle_id="sbp_workflow_execution", reason="SBP access"),
    ]

    result = await check_sbp_email_allowed(email="sbp.user@example.com", bundles=bundles)

    assert result is not None
    assert result.message == "SBP workflow execution requires an Australian institutional email address."
    institution_check.assert_awaited_once_with("sbp.user@example.com")
