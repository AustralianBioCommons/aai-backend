"""
Custom error responses
"""
from typing import Callable

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import Response

from schemas.responses import FieldError, RegistrationErrorResponse


class RegistrationRoute(APIRoute):
    """
    Custom route class for registration requests, returns RegistrationErrorResponse
    for validation errors.
    """
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            try:
                return await original_route_handler(request)
            except RequestValidationError as exc:
                return handle_registration_error(exc)

        return custom_route_handler


def handle_registration_error(exc: RequestValidationError):
    field_errors = []
    for error in exc.errors():
        loc, msg = error["loc"], error["msg"]
        filtered_loc = loc[1:] if loc[0] in ("body", "query", "path") else loc
        field_string = ".".join(filtered_loc)
        field_errors.append(FieldError(field=field_string, message=msg))
    response = RegistrationErrorResponse(
        message="Invalid data submitted",
        field_errors=field_errors,
    )
    return JSONResponse(status_code=400, content=jsonable_encoder(response))
