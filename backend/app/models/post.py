from pydantic import BaseModel 
from typing import Optional

class Post(BaseModel): 
    title : str
    content : Optional[str] = None  
    user : Optional[str] = None  