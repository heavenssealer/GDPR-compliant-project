from fastapi import Request
from fastapi.responses import JSONResponse
import jwt 
import os 
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED

SECRET_KEY = os.getenv("JWT_SECRET")

async def auth_middleware(request: Request, call_next):
    try:
        auth = request.headers.get("Authorization")
        if not auth:
            raise ValueError("Authorization header missing")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ValueError("Malformed auth header")
        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        request.state.user = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return await call_next(request)

    except jwt.ExpiredSignatureError:
        return JSONResponse({"detail": "Token expired"}, status_code=HTTP_401_UNAUTHORIZED)

    except jwt.PyJWTError:
        return JSONResponse({"detail": "Invalid token"}, status_code=HTTP_401_UNAUTHORIZED)

    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=HTTP_400_BAD_REQUEST)