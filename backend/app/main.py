from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi import Query
from starlette.status import HTTP_409_CONFLICT, HTTP_500_INTERNAL_SERVER_ERROR, HTTP_201_CREATED, HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_429_TOO_MANY_REQUESTS, HTTP_404_NOT_FOUND
from dotenv import load_dotenv
from markupsafe import escape
from passlib.context import CryptContext
from datetime import timezone, timedelta, datetime
from bson import ObjectId
from pymongo.collection import Collection

from app.models.post import Post
from app.models.connectionDetails import ConnectionDetails
from app.middlewares.authenticationMiddleware import authentication_middleware
from app.middlewares.authorizationMiddleware import authorization_middleware
from app.middlewares.sanitizationMiddleware import sanitization_middleware
from app.utility.utility import access_collection, get_all_users
from app.utility.utility import generate_jwt

import os 

pwd_context = CryptContext(schemes=["argon2"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# loading of environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("JWT_SECRET")
LIVING_TIME = os.getenv("ACCESS_TOKEN_EXPIRES_AFTER_MINUTES")
ALGORITHM = "HS256"

ISE = "Internal server error"
PNF = "Post not found"
UNF = "User not found"
AF = "Authentication failure"

# initializing the app 
app = FastAPI()

app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["http://localhost:8080"],
    allow_methods=["POST", "GET", "OPTIONS", "PUT", "DELETE"], 
    allow_headers=["Content-Type", "Authorization"], 
    allow_credentials=True
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "Invalid connection details : check mail or password format (13 - 50 characters, uppercase, lowercase, number, special character (no <>))"},
    )

# middlewares for sanitization and authentication 
app.middleware("http")(sanitization_middleware)
app.middleware("http")(authorization_middleware)
app.middleware("http")(authentication_middleware)




# test route to check if the server is up and running (used only by admin users)
@app.get("/")
async def root():
    return {"message" : "Server running"}

# route used to log in a registered user
@app.post("/login")
async def login(data : ConnectionDetails): 
    email, password = escape(data.email), escape(data.password)
    try : 
        users = await access_collection("users")
        query = {"email" : email}

        user = users.find_one(query)
        
        if not user : 
            return JSONResponse({"detail" : AF})
        else : 
            # first, we check how many connection attempts 
            connection_attempts = user['connection_attempts']
            # if 5 or more connection attempts in the counter 
            if connection_attempts >= 5 : 
                # checking how much time since last connection attempt
                last_connection_attempt = user['last_connection_attempt'].replace(tzinfo=timezone.utc)
                elapsed = datetime.now(timezone.utc) - last_connection_attempt
                # if 1hr or more passed since last try, reset the counter
                if elapsed >= timedelta(hours=1):
                    users.update_one({"email" : email}, {"$set" : {"connection_attempts" : 0, "last_connection_attempt" : datetime.now(timezone.utc)}})
                else : 
                    return JSONResponse({"detail" : "Too many connection attempts"}, status_code=HTTP_429_TOO_MANY_REQUESTS)
            # we check if the password is correct by comparing against the database
            if pwd_context.verify(password, user['password']): 
                users.update_one({"email" : email}, {"$set" : {"connection_attempts" : 0, "last_connection_attempt" : datetime.now(timezone.utc)}})
                user_id = str(user['_id'])
                # generating the JWT 
                encoded_jwt = generate_jwt(user_id=user_id, email=email)
                return JSONResponse({"detail" : "Authentication success", "token" : encoded_jwt}, status_code=HTTP_200_OK)
            else : 
                # if incorrect password, adding 1 connection attempt
                connection_attempts += 1 
                users.update_one({"email" : email}, {"$set" : {"connection_attempts" : connection_attempts, "last_connection_attempt" : datetime.now(timezone.utc)}})
                return JSONResponse({"detail" : AF}, status_code=HTTP_401_UNAUTHORIZED)
    except Exception as e : 
        print("ERROR : ", e)
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)
   

# route used to register a new user
@app.post("/register")
async def register(data : ConnectionDetails):

    email, password = escape(data.email), escape(data.password) 

    # password hash with argon2
    hashed_password = pwd_context.hash(password)

    try : 
        users = await access_collection("users")
        query = {"email" : email}

        user = users.find_one(query)
        if user :
            return JSONResponse({"detail": "The account already exists"}, status_code=HTTP_409_CONFLICT)
        else : 
            # by default, role : user 
            users.insert_one({"email" : email, "password" : hashed_password, "connection_attempts" : 0, "last_connection_attempt" : datetime.now(timezone.utc), "role" : "user" })
            return JSONResponse({"detail" : "Account created successfully"}, status_code=HTTP_201_CREATED)
    except Exception  :
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)


@app.post('/post')
async def add_post(req : Request, post : Post): 
    title, content = escape(post.title), escape(post.content)
    user = req.state.user['user_id']
    try : 
        posts = await access_collection("posts")
        query = {"title" : title, "user" : ObjectId(user)}
        queried_post = posts.find_one(query)
        if queried_post : 
            return JSONResponse({"detail" : "Post with this title already exists"}, status_code=HTTP_409_CONFLICT)
        else : 
            posts.insert_one({"title" : title, "content" : content, "user" : ObjectId(user)})
            return JSONResponse({"detail" : "Post created successfully"}, status_code=HTTP_201_CREATED)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)

@app.get("/post")
async def get_post(req: Request, title: str = Query(..., min_length=1)):
    title = escape(title)
    user = req.state.user['user_id']
    try : 
        posts = await access_collection("posts")
        query = {"title" : title, "user" : ObjectId(user)}
        queried_post = posts.find_one(query)
        if queried_post : 
            returned_post = {
                "title" : queried_post['title'], 
                "content" : queried_post['content'], 
            }
            return JSONResponse({"detail" : "Request successful", "post" : returned_post}, HTTP_200_OK)
        else : 
            return JSONResponse({"detail" : PNF}, status_code=HTTP_404_NOT_FOUND)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)
    
@app.put('/post')
async def update_post(req : Request, post : Post): 
    title, content = escape(post.title), escape(post.content)
    user = req.state.user['user_id']
    try : 
        posts = await access_collection("posts")
        query = {"title" : title, "user" : ObjectId(user)}
        queried_post = posts.find_one(query)
        if queried_post : 
            posts.update_one({"title" : title, "user" : ObjectId(user)}, {"$set" : {"content" : content}})
            return JSONResponse({"detail" : "Post updated"}, status_code=HTTP_200_OK)
        else : 
            return JSONResponse({"detail" : PNF}, status_code=HTTP_404_NOT_FOUND)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)


@app.delete('/post')
async def delete_post(req : Request, post : Post): 
    title = escape(post.title)
    user = req.state.user["user_id"]
    try : 
        posts = await access_collection("posts")
        query = {"title" : title, "user" : ObjectId(user)}
        queried_post = posts.find_one(query)
        if queried_post: 
            posts.delete_one({"title" : title, "user" : ObjectId(user)})
            return JSONResponse({"detail": "Post deleted"}, status_code=HTTP_200_OK)
        else : 
            return JSONResponse({"detail" : PNF}, status_code=HTTP_404_NOT_FOUND)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)

@app.put('/user')
async def update_email(req : Request, data : ConnectionDetails):
    email , password = escape(data.email), escape(data.password)
    user_ = req.state.user['user_id']
    try : 
        users : Collection  = await access_collection("users")
        query = {'_id' : ObjectId(user_)}
        user = users.find_one(query)
        if user: 
            if  pwd_context.verify(password, user['password']) : 
                users.update_one({"_id" : ObjectId(user_)}, {"$set" : {"email" : email}})
                return JSONResponse({'detail' : "Email updated"}, status_code=HTTP_200_OK)
            else : 
                return JSONResponse({"detail" : AF}, status_code=HTTP_401_UNAUTHORIZED)
        else : 
            return JSONResponse({"detail" : UNF}, status_code=HTTP_404_NOT_FOUND)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)
    

@app.get('/user')
async def get_user(req : Request) : 
    user = req.state.user['user_id']
    try : 
        users : Collection = await access_collection('users')
        query = {"_id" : ObjectId(user)}
        user = users.find_one(query)
        if user : 
            users_details = {
                "email" : user['email'], 
                "role" : user['role'], 
                "last_connection" : str(user['last_connection_attempt'])
            }
            return JSONResponse({"detail" : "User details retrieved", "content" : users_details}, status_code=HTTP_200_OK)
        else : 
            return JSONResponse({"detail" : UNF}, status_code=HTTP_404_NOT_FOUND)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)


@app.delete('/user')
async def delete_user(req : Request, data : ConnectionDetails) : 
    user_ = req.state.user["user_id"]
    email , password = escape(data.email), escape(data.password)
    try : 
        users : Collection = await access_collection('users')
        posts : Collection = await access_collection('posts')
        query = {"_id" : ObjectId(user_), "email" : email}
        user = users.find_one(query)
        if user : 
            if  pwd_context.verify(password, user['password']) : 
                users.delete_one({"_id" : ObjectId(user_)})
                posts.delete_many({"user" : ObjectId(user_)})
                return JSONResponse({"detail" : "Deleted all user related content"}, status_code=HTTP_200_OK)
            else : 
                return JSONResponse({"detail" : AF}, status_code=HTTP_401_UNAUTHORIZED)
        else : 
            return JSONResponse({"detail" : UNF}, status_code=HTTP_404_NOT_FOUND)
    except Exception : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)
# route to get the users of the application, middleware ensures that only admin users can access this route

@app.get("/users")
async def get_users(req : Request):
    try : 
        users : list = await get_all_users()
        for i in range(len(users)): 
            users[i].update({"_id" : str(users[i]["_id"])})
            users[i].update({"last_connection_attempt" : str(users[i]["last_connection_attempt"])})
            users[i].update({"password": "*********************"})
        return JSONResponse({"detail" : users}, status_code=HTTP_200_OK)
    except Exception  : 
        return JSONResponse({"detail" : ISE}, status_code=HTTP_500_INTERNAL_SERVER_ERROR)

