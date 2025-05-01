from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer

from auth.management import get_management_token
from auth.validator import verify_jwt
from schemas.user import User

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    access_token = verify_jwt(token)
    return User(access_token=access_token)

@app.get("/")
def public_route():
    return {"message": "Public route"}

@app.get("/private")
def private_route(user=Depends(get_current_user)):
    return {"message": "Private route", "user_claims": user, "management_token": get_management_token()}
