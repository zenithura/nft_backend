"""Simple Admin Authentication Router."""
import os
import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin Auth"])

# Admin credentials from environment
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret-key")
JWT_ALGORITHM = "HS256"
ADMIN_TOKEN_EXPIRE_MINUTES = 480  # 8 hours


from typing import Optional


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminLoginResponse(BaseModel):
    success: bool
    message: str
    access_token: Optional[str] = None
    admin: Optional[dict] = None


class AdminSessionResponse(BaseModel):
    authenticated: bool
    admin: Optional[dict] = None


def create_admin_token(username: str) -> str:
    """Create JWT token for admin session."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ADMIN_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": "ADMIN",
        "type": "admin",
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_admin_token(token: str) -> dict:
    """Verify admin JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "admin" or payload.get("role") != "ADMIN":
            return None
        return payload
    except Exception:
        return None


@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(login_data: AdminLoginRequest):
    """Simple admin login - checks username/password, returns JWT token."""
    username = login_data.username.strip()
    password = login_data.password.strip()
    
    logger.info(f"Admin login attempt for user: {username}")
    
    # Simple credential check
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        logger.warning(f"Failed admin login for user: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Create token
    token = create_admin_token(username)
    
    logger.info(f"Admin login successful for user: {username}")
    
    return AdminLoginResponse(
        success=True,
        message="Login successful",
        access_token=token,
        admin={"username": username, "role": "ADMIN"}
    )


@router.get("/session", response_model=AdminSessionResponse)
async def check_admin_session(request: Request):
    """Check if admin session is valid via Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        return AdminSessionResponse(authenticated=False, admin=None)
    
    token = auth_header.replace("Bearer ", "")
    payload = verify_admin_token(token)
    
    if not payload:
        return AdminSessionResponse(authenticated=False, admin=None)
    
    return AdminSessionResponse(
        authenticated=True,
        admin={
            "username": payload.get("sub"),
            "role": payload.get("role")
        }
    )


@router.post("/logout")
async def admin_logout():
    """Admin logout - client should remove token from localStorage."""
    return {"success": True, "message": "Logged out successfully"}


# Dependency for protected routes
def get_admin_user(request: Request) -> dict:
    """Get admin user from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    token = auth_header.replace("Bearer ", "")
    payload = verify_admin_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    return {
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "user_id": None
    }


def require_admin_auth(request: Request) -> dict:
    """Dependency to require admin authentication."""
    admin = get_admin_user(request)
    if admin.get("role") != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return admin
