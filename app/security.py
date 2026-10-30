import os, secrets, hashlib
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET = os.getenv("SECRET_KEY", "INSECURE-DEV-ONLY-CHANGE-ME")
ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    return pwd.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd.verify(password, hashed)

def make_access_token(user_id: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "720")))
    return jwt.encode({"sub": str(user_id), "exp": exp}, SECRET, algorithm=ALGORITHM)

def decode_token(token: str) -> int | None:
    try:
        return int(jwt.decode(token, SECRET, algorithms=[ALGORITHM])["sub"])
    except (JWTError, ValueError, KeyError):
        return None

def new_device_token() -> str:
    return secrets.token_urlsafe(40)

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
