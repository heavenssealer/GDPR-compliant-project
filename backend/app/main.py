from fastapi import FastAPI, Request, Response, HTTPException
from models.user import User
from middlewares.authMiddleware import auth_middleware
from starlette.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.middleware("http")(auth_middleware)


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "detail": exc.detail},
        headers=exc.headers or {},
    )


@app.get("/")
async def root():
    return {"message" : "Server running."}

@app.get("/users")
async def get_users():
    return {"message" : "Getting the users."}

