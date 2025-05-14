from pydantic import BaseModel 

class User(BaseModel): 
    email : str 
    password : str 

    def get_email(self):
        return self.email

    def get_password(self): 
        return self.email 