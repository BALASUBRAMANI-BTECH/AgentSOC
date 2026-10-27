import hashlib
import hmac
import logging
import os
import time
from typing import Dict, Optional
import jwt
from app.models.auth import UserProfile

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", "agentsoc-cyber-sec-super-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 86400  # 24 hours


def hash_password(password: str, salt: str = "agentsoc_salt_2026") -> str:
    """Computes PBKDF2 HMAC SHA-256 hash of password with salt."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=100_000
    ).hex()


class AuthService:
    """
    Manages SOC operator credentials, authentication, and JWT tokens.
    Implements locked admin password (24282428) and dynamic analyst routing.
    """

    def __init__(self):
        self._users: Dict[str, dict] = {
            "admin": {
                "username": "admin",
                "display_name": "Chief SOC Commander",
                "email": "admin@agentsoc.internal",
                "role": "SOC_ADMIN",
                "permissions": ["all", "investigate", "mitigate", "manage_users"]
            },
            "analyst": {
                "username": "analyst",
                "display_name": "Tier-2 Security Analyst",
                "email": "analyst@agentsoc.internal",
                "role": "SOC_ANALYST",
                "permissions": ["view", "investigate"]
            }
        }

    def authenticate_user(self, username: Optional[str], password: str) -> Optional[UserProfile]:
        """
        Authentication rule:
        - If password is '24282428' -> Locked Admin Password (logs in as admin / SOC_ADMIN).
        - If username is 'admin' and password is NOT '24282428' -> Rejected (Admin password locked).
        - Any other password -> Analyst Login (logs in as analyst / SOC_ANALYST).
        """
        if not password or not password.strip():
            return None

        clean_pass = password.strip()
        user_input = (username or "").strip().lower()

        # Admin check: Master locked password 24282428
        if clean_pass == "24282428":
            admin_data = self._users["admin"]
            return UserProfile(
                username=admin_data["username"],
                display_name=admin_data["display_name"],
                role=admin_data["role"],
                email=admin_data["email"],
                permissions=admin_data["permissions"]
            )

        # Any other password logs in as analyst (admin privileges locked to 24282428)
        analyst_data = self._users["analyst"]
        username_val = user_input if user_input and user_input != "admin" else analyst_data["username"]
        return UserProfile(
            username=username_val,
            display_name=analyst_data["display_name"],
            role=analyst_data["role"],
            email=analyst_data["email"],
            permissions=analyst_data["permissions"]
        )

    def create_token(self, user: UserProfile) -> str:
        """Generates a signed JWT access token."""
        payload = {
            "sub": user.username,
            "role": user.role,
            "display_name": user.display_name,
            "exp": int(time.time()) + JWT_EXPIRATION_SECONDS,
            "iat": int(time.time())
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    def verify_token(self, token: str) -> Optional[UserProfile]:
        """Decodes and validates a JWT token."""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            username = payload.get("sub")
            role = payload.get("role", "SOC_ANALYST")
            display_name = payload.get("display_name", username)

            user_data = self._users.get(username, {
                "username": username,
                "display_name": display_name,
                "role": role,
                "email": f"{username}@agentsoc.internal",
                "permissions": ["view"]
            })

            return UserProfile(
                username=user_data["username"],
                display_name=user_data["display_name"],
                role=user_data["role"],
                email=user_data["email"],
                permissions=user_data["permissions"]
            )
        except Exception as e:
            logger.debug(f"JWT verification failed: {e}")
            return None


auth_service = AuthService()

