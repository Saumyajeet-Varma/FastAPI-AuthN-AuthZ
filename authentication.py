import os
from fastapi import FastAPI, HTTPException, Request
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

class LoginRequest(BaseModel):
    username: str
    password: str


class User(BaseModel):
    id: str
    username: str
    hashed_password: str


# -------- Fake DB --------

users_db: list[User] = []

users_db.append(
    User(
        id=str(uuid.uuid4()),
        username="user1",
        hashed_password=pwd_context.hash("password123")
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
        "exp": expire
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return token


def verify_token(token: str):

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("id")
        username = payload.get("username")

        if user_id is None or username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        return {"id": user_id, "username": username}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------- Routes --------

@app.post("/login")
def login(data: LoginRequest):

    user = get_user(data.username)

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    token = create_token(user)

    return {"access_token": token}


@app.get("/protected")
def protected(request: Request):

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    token = auth_header.split(" ")[1]

    user_data = verify_token(token)

    return {
        "message": f"Hello {user_data['username']}",
        "user_id": user_data["id"]
    }