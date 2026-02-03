from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt

pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12, deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)  

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def generate_jwt(data: dict, expire_minutes: int, secret_key: str, algorithm: str):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expire_minutes)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt


def verify_jwt(token: str, secret_key: str, algorithm: str):
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except JWTError:
        return None

