from fastapi import FastAPI
from routers import user
from routers import galaxy_register

app = FastAPI()


@app.get("/")
def public_route():
    return {"message": "AAI Backend API"}


app.include_router(user.router)
app.include_router(galaxy_register.router)