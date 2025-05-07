from fastapi import Depends, FastAPI

from auth.management import get_management_token
from auth.validator import get_current_user
from routers import user

app = FastAPI()


@app.get("/")
def public_route():
    return {"message": "Public route"}


@app.get("/private")
def private_route(user=Depends(get_current_user)):
    return {
        "message": "Private route",
        "user_claims": user,
        "management_token": get_management_token()
    }


app.include_router(user.router)