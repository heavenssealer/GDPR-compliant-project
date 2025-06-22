from pydantic import BaseModel

class ConsentForm(BaseModel):
    necessary_cookies: bool = True  # toujours vrai, non modifiable
    analytics_cookies: bool
    marketing_cookies: bool
    partners_cookies: bool