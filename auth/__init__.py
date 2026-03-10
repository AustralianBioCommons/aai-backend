from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

auth0_security = HTTPBearer(auto_error=False, description="Auth0 bearer token")

async def get_auth0_token(
    bearer_token: HTTPAuthorizationCredentials | None = Depends(auth0_security),
) -> str:
    if bearer_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return bearer_token.credentials
