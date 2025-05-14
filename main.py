from fastapi import FastAPI

from routers import user

app = FastAPI()


@app.get("/")
def public_route():
    return {"message": "AAI Backend API"}


app.include_router(user.router)
