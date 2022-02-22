from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "cfa9d500d18dfb39cca332457c2b18442e6914bc3b3a51743ff4de15dd42ec64"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Setting up a fake DB for testing

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Setup pydantic User Model

class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    password: str
    disabled: Optional[bool] = None


class UserInDB(User):
    password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Creates an instance of the OAuth2PasswordBearer. Passed user/login endpoint to receive the username and password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="user/login")

app = FastAPI()


# Functions to  hash and verify password using bcrypt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


# Endpoint to register user
# Accepts Username, Email, Password
# Password is hashed, and all inputs are passed on to fake_users_db

@app.post("/user/register")
def create_user(request: User):
    hashed_pass = get_password_hash(request.password)
    user_object = dict(request)
    user_object["password"] = hashed_pass
    fake_users_db[user_object["username"]] = user_object
    return {"res":"created"}

# Function to retrieve created user from fake DB

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

# Function to authenticate user by verifying password (also checks for presence in DB)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

# Creates access token encoded based on SECRET_KEY and ALGORITHM

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# get_current_user receives token from oauth2_scheme as a str and returns the user
# decodes received token and returns current user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# checks if disabled field is true, and returns current user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# OAuth2PasswordRequestForm declares form body with Username and Password 

@app.post("/user/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/user/profile", response_model=User)
async def read_users_profile(current_user: User = Depends(get_current_active_user)):
    return current_user
