from pydantic import BaseModel, EmailStr, StringConstraints
from typing import Annotated, Optional

class ConnectionDetails(BaseModel): 
    email : EmailStr
    password: Annotated[str,StringConstraints(min_length=13, max_length=50)]
    connection_attempts: Optional[int] = None
    last_connection_attempt: Optional[int] = None
    role : Optional[str] = None  