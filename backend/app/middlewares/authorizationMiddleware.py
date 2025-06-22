from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED

from app.utility.utility import user_details

import os 



SECRET_KEY = os.getenv("JWT_SECRET", "TOTO")
EXEMPT_PATHS = {"/register", "/login", "/post", "/user", "/set-consent"}


async def authorization_middleware(req: Request, call_next):
    if req.url.path in EXEMPT_PATHS:
        return await call_next(req)
    # Let CORS preflight through
    if req.method == "OPTIONS":
        return await call_next(req)
    try:
        user = await user_details(req.state.user["user_id"])
        if user["role"] != "admin" : 
            return JSONResponse({"detail" : "User is not admin"}, status_code=HTTP_401_UNAUTHORIZED)
        else : 
            return await call_next(req)
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=HTTP_400_BAD_REQUEST)