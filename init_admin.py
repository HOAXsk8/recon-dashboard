import sys
import os
import datetime

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import sync_db
from app.security import get_password_hash, generate_totp_secret

def init_admin():
    users_col = sync_db["users"]
    scanners_col = sync_db["scanners"]
    
    # 1. Initialize Admin User
    username = "admin"
    if not users_col.find_one({"username": username}):
        password = os.getenv("ADMIN_INITIAL_PASSWORD", "ChangeMe123!")
        if password == "ChangeMe123!":
            print("WARNING: ADMIN_INITIAL_PASSWORD not set. Using default: ChangeMe123!")
        
        hashed_password = get_password_hash(password)
        totp_secret = os.getenv("ADMIN_INITIAL_TOTP_SECRET") or generate_totp_secret()
        
        user_data = {
            "username": username,
            "hashed_password": hashed_password,
            "totp_secret": totp_secret,
            "role": "admin",
            "is_admin": True,
            "disabled": False,
            "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        users_col.insert_one(user_data)
        
        print("--- Initial Admin User Created ---")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"TOTP Secret: {totp_secret}")
        print("IMPORTANT: Save the TOTP Secret in your authenticator app.")
        print("----------------------------------")
    else:
        print(f"User {username} already exists.")

if __name__ == "__main__":
    init_admin()
