from dotenv import load_dotenv
from bson import ObjectId
from datetime import datetime, timezone, timedelta
from pymongo.collection import Collection

from app.database.db import connect_to_db

import jwt 
import os 

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("JWT_SECRET")
LIVING_TIME = os.getenv("ACCESS_TOKEN_EXPIRES_AFTER_MINUTES")
ALGORITHM = "HS256"


# function to generate a json webtoken (JWT) if the user exists and the password is correct 
def generate_jwt(user_id : str, email : str):
    delta = timedelta(minutes=int(LIVING_TIME))
    payload = { 
        "user_id" : user_id,
        "email" : email
    }
    jwt_expires = datetime.now(timezone.utc) + delta
    payload.update({'exp' : jwt_expires})
    return jwt.encode(payload, SECRET_KEY, algorithm = ALGORITHM)

async def user_details(id:str):
    client = await connect_to_db(uri=MONGO_URI)
    db = client.get_database("website")
    users = db.get_collection("users")
    query = {"_id" : ObjectId(id)}
    user = users.find_one(query)
    return user 

async def get_all_users(): 
    client = await connect_to_db(uri=MONGO_URI)
    db = client.get_database('website')
    users = db.get_collection("users")
    users_ = list(users.find({}))
    return users_

async def access_collection(collection : str) -> Collection : 
    client = await connect_to_db(uri=MONGO_URI)
    db = client.get_database('website')
    var = db.get_collection(collection)
    return var 