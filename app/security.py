import os
from datetime import datetime, timedelta
from typing import Optional

import pyotp
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Request

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # In a production environment, this should probably raise a RuntimeError
    # For now, we will ensure it is not a known hardcoded default.
    SECRET_KEY = os.urandom(32).hex() 

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_totp(secret: str, code: str):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Netbytes.cloud")

def validate_password(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, ""
