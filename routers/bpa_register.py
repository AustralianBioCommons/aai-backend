import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth.ses import EmailService
from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser, PlatformEnum
from db.setup import get_db_session
from routers.errors import RegistrationRoute
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.bpa import BPARegistrationRequest
from schemas.responses import RegistrationErrorResponse, RegistrationResponse
from schemas.service import Resource, Service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/bpa",
    tags=["bpa", "registration"],
    # Overriding route class to handle registration errors
    route_class=RegistrationRoute
)


def send_approval_email(registration: BPARegistrationRequest, bpa_resources: list[Resource]):
    email_service = EmailService()
    approver_email = "aai-dev@biocommons.org.au"
    subject = "New BPA User Access Request"

    org_list_html = "".join(
        f"<li>{res.name} (ID: {res.id})</li>" for res in bpa_resources
    )

    body_html = f"""
        <p>A new user has requested access to one or more organizations in the BPA service.</p>
        <p><strong>User:</strong> {registration.fullname} ({registration.email})</p>
        <p><strong>Requested access to:</strong></p>
        <ul>{org_list_html}</ul>
        <p>Please <a href='https://aaiportal.test.biocommons.org.au/requests'>log into the AAI Admin Portal</a> to review and approve access.</p>
    """

    email_service.send(approver_email, subject, body_html)


def _get_bpa_resources(registration: BPARegistrationRequest, settings: Settings, update_time: datetime) -> list[Resource]:
    bpa_resources = []
    for org_id, is_selected in registration.organizations.items():
        if not is_selected:
            continue
        if org_id not in settings.organizations:
            raise HTTPException(
                status_code=400, detail=f"Invalid organization ID: {org_id}"
            )
        resource = Resource(
            id=org_id,
            name=settings.organizations[org_id],
            status="pending",
            last_updated=update_time,
            initial_request_time=update_time,
            updated_by="system",
        ).model_dump(mode="json")
        bpa_resources.append(resource)
    return bpa_resources


def _get_bpa_service_request(registration: BPARegistrationRequest, settings: Settings, update_time: datetime) -> Service:
    bpa_resources = _get_bpa_resources(registration, settings, update_time)
    return Service(
        name="Bioplatforms Australia Data Portal",
        id="bpa",
        initial_request_time=update_time,
        status="pending",
        last_updated=update_time,
        updated_by="system",
        resources=bpa_resources,
    )


@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_bpa_user(
    registration: BPARegistrationRequest,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings),
    db_session: Session = Depends(get_db_session),
    auth0_client: Auth0Client = Depends(get_auth0_client)
):
    """Register a new BPA user with selected organization resources."""
    now = datetime.now(timezone.utc)
    bpa_service = _get_bpa_service_request(registration=registration, settings=settings, update_time=now)

    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_bpa_registration(
        registration=registration, bpa_service=bpa_service
    )

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        _create_bpa_user_record(auth0_user_data, db_session)

        if bpa_service.resources and settings.send_email:
            background_tasks.add_task(send_approval_email, registration, bpa_resources=bpa_service.resources)

        return {"message": "User registered successfully", "user": auth0_user_data.model_dump(mode="json")}

    # Return HTTP status errors as RegistrationErrorResponse
    except HTTPStatusError as e:
        # Catch specific errors where possible and return a useful error message
        if e.response.status_code == 409:
            response = RegistrationErrorResponse(message="Username or email already in use")
        else:
            response = RegistrationErrorResponse(message=f"Auth0 error: {str(e.response.text)}")
        return JSONResponse(status_code=400, content=response.model_dump(mode="json"))
    # Unknown errors should return 500
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to register user: {str(e)}"
        )


def _create_bpa_user_record(auth0_user_data: Auth0UserData, session: Session) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
    bpa_membership = db_user.add_platform_membership(
        platform=PlatformEnum.BPA_DATA_PORTAL,
        db_session=session,
        auto_approve=True
    )
    session.add(db_user)
    session.add(bpa_membership)
    session.commit()
    return db_user
