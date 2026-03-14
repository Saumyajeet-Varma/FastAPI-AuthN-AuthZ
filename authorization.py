import os
from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uuid
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_IN_MINUTES"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# -------- Models --------

class AuthRequest(BaseModel):
    username: str
    password: str


class User(BaseModel):
    id: str
    username: str
    hashed_password: str
    role: str


# -------- Fake DB --------

users_db: list[User] = []

users_db.append(
    User(
        id=str(uuid.uuid4()),
        username="admin1",
        hashed_password=pwd_context.hash("password123"),
        role="admin"
    )
)

users_db.append(
    User(
        id=str(uuid.uuid4()),
        username="user1",
        hashed_password=pwd_context.hash("password123"),
        role="user"
    )
)


# -------- Utility Functions --------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str):
    for user in users_db:
        if user.username == username:
            return user
    return None


def create_token(user: User):

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "exp": expire
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return token


def verify_token(token: str):

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        return payload

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------- Dependency: Authentication --------

def get_current_user(request: Request):

    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = auth_header.split(" ")[1]

    user_data = verify_token(token)

    return user_data


# -------- Dependency: Authorization --------

def require_admin(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return user


# -------- Routes --------

@app.post("/register")
def register(data: AuthRequest):

    existing_user = get_user(data.username)

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(data.password)

    new_user = User(
        id=str(uuid.uuid4()),
        username=data.username,
        hashed_password=hashed_password,
        role="user"  # default role
    )

    users_db.append(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "role": new_user.role
    }

@app.post("/login")
def login(data: AuthRequest):

    user = get_user(data.username)

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    token = create_token(user)

    return {"access_token": token}


# -------- Authenticated Route --------

@app.get("/protected")
def protected(user=Depends(get_current_user)):

    return {
        "message": f"Hello {user['username']}",
        "role": user["role"]
    }


# -------- Admin Only Route --------

@app.get("/admin")
def admin_dashboard(user=Depends(require_admin)):

    return {
        "message": f"Welcome admin {user['username']}"
    }