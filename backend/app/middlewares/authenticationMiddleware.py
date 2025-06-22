from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from bson import ObjectId

from app.utility.utility import access_collection

import jwt 
import os 


SECRET_KEY = os.getenv("JWT_SECRET", "TEST")
EXEMPT_PATHS = {"/register", "/login"}
MONGO_URI = os.getenv("MONGO_URI")

async def authentication_middleware(req: Request, call_next):

    #  creating an exception for the paths that don't need authentication (e.g. registration)
    if req.url.path in EXEMPT_PATHS:
        return await call_next(req)
    
    # Let CORS preflight through
    if req.method == "OPTIONS":
        return await call_next(req)

    try:
        auth = req.headers.get("Authorization")
        if not auth:
            raise ValueError("Authorization header missing")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ValueError("Invalid authorization header format")
        
        req.state.user = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # checking if the mail exists or not (to prevent deleted users from still using their token)
        users = await access_collection('users')
        query = {"_id" : ObjectId(req.state.user['user_id']), "email" : req.state.user['email']}
        user = users.find_one(query)
        if not user : 
            return JSONResponse({"detail" : "Broken token : user invalid"}, status_code=HTTP_401_UNAUTHORIZED)
        return await call_next(req)

    except jwt.ExpiredSignatureError:
        return JSONResponse({"detail": "Token expired"}, status_code=HTTP_401_UNAUTHORIZED)

    except jwt.PyJWTError:
        return JSONResponse({"detail": "Invalid token"}, status_code=HTTP_401_UNAUTHORIZED)

    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=HTTP_400_BAD_REQUEST)