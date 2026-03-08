from fastapi.security import HTTPBearer

auth0_security = HTTPBearer(description="Auth0 bearer token")
