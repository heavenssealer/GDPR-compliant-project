from fastapi import Request 
from fastapi.responses import JSONResponse
from starlette.status import HTTP_413_REQUEST_ENTITY_TOO_LARGE

async def sanitization_middleware(req : Request, call_next) : 
    MAX_SIZE = 500_000

    # header based detection of size 
    content_length = req.headers.get("content-length")
    if content_length and int(content_length) > MAX_SIZE : 
            return JSONResponse({"detail" : "Payload too large"}, status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    
    # body size based detection
    body = await req.body()
    if len(body) > MAX_SIZE: 
        return JSONResponse({"detail" : "Payload too large"}, status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    
    return await call_next(req)
    
    
      
