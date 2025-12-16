from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from jose import JWTError, jwt

from config import Settings

ALGORITHM = "HS256"
TOKEN_EXPIRATION_MINUTES = 5


def create_registration_token(settings: Settings) -> str:
    """
    Create a JWT token for registration
    """
    expire = datetime.now(UTC) + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload = {
        "purpose": "register",
        "exp": expire,
        "iat": datetime.now(UTC)
    }
    token = jwt.encode(payload, key=settings.jwt_secret_key, algorithm=ALGORITHM)
    return token


def verify_registration_token(token: str, settings: Settings):
    try:
        payload = jwt.decode(token, key=settings.jwt_secret_key, algorithms=[ALGORITHM])
        if payload.get("purpose") != "register":
            raise JWTError("Invalid purpose")
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
