import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import sync_db
from app.security import get_password_hash, generate_totp_secret

def init_admin():
    users_col = sync_db["users"]
    
    username = "admin"
    if users_col.find_one({"username": username}):
        print(f"User {username} already exists.")
        return

    password = "ChangeMe123!" # User should change this
    hashed_password = get_password_hash(password)
    totp_secret = generate_totp_secret()
    
    user_data = {
        "username": username,
        "hashed_password": hashed_password,
        "totp_secret": totp_secret,
        "is_admin": True,
        "disabled": False,
        "created_at": str(sync_db.client.admin.command("serverStatus")["localTime"])
    }
    
    users_col.insert_one(user_data)
    
    print("--- Initial Admin User Created ---")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"TOTP Secret: {totp_secret}")
    print("IMPORTANT: Save the TOTP Secret in your authenticator app (e.g., Google Authenticator).")
    print("----------------------------------")

if __name__ == "__main__":
    init_admin()
