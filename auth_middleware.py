"""Authentication middleware for protecting routes."""
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from supabase import Client

from database import get_supabase_admin
from auth_utils import verify_token
from cache import get as cache_get, set as cache_set

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Client = Depends(get_supabase_admin)
) -> dict:
    """Get current authenticated user from JWT token."""
    # #region agent log
    import time
    import json
    middleware_start = time.time()
    with open('/home/eniac/Desktop/NFT-TICKETING/.cursor/debug.log', 'a') as f:
        f.write(json.dumps({"location":"auth_middleware.py:13","message":"get_current_user start","data":{},"timestamp":int(middleware_start*1000),"sessionId":"debug-session","runId":"run1","hypothesisId":"H5"})+"\n")
    # #endregion
    
    token = credentials.credentials
    payload = verify_token(token, token_type="access")
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    # Get user from database (with caching for performance)
    try:
        cache_key = f"user:{user_id}"
        cached_user = cache_get(cache_key)
        if cached_user is not None:
            # #region agent log
            with open('/home/eniac/Desktop/NFT-TICKETING/.cursor/debug.log', 'a') as f:
                f.write(json.dumps({"location":"auth_middleware.py:44","message":"User cache hit","data":{"user_id":user_id},"timestamp":int(time.time()*1000),"sessionId":"debug-session","runId":"run1","hypothesisId":"H1"})+"\n")
            # #endregion
            # Still check if user is active (cached users might become inactive)
            if not cached_user.get("is_active", True):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is inactive"
                )
            return cached_user
        
        # #region agent log
        db_query_start = time.time()
        with open('/home/eniac/Desktop/NFT-TICKETING/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"location":"auth_middleware.py:56","message":"User DB query start","data":{"user_id":user_id},"timestamp":int(db_query_start*1000),"sessionId":"debug-session","runId":"run1","hypothesisId":"H1"})+"\n")
        # #endregion
        
        response = db.table("users").select("*").eq("user_id", int(user_id)).execute()
        
        # #region agent log
        db_query_duration = (time.time() - db_query_start) * 1000
        with open('/home/eniac/Desktop/NFT-TICKETING/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"location":"auth_middleware.py:60","message":"User DB query complete","data":{"user_id":user_id,"duration_ms":db_query_duration,"found":bool(response.data)},"timestamp":int(time.time()*1000),"sessionId":"debug-session","runId":"run1","hypothesisId":"H1"})+"\n")
        # #endregion
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        user = response.data[0]
        
        # Check if user is active
        if not user.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )
        
        # Cache user for 60 seconds (user data doesn't change frequently)
        cache_set(cache_key, user, ttl=60)
        
        # #region agent log
        total_duration = (time.time() - middleware_start) * 1000
        with open('/home/eniac/Desktop/NFT-TICKETING/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"location":"auth_middleware.py:69","message":"get_current_user complete","data":{"user_id":user_id,"total_duration_ms":total_duration},"timestamp":int(time.time()*1000),"sessionId":"debug-session","runId":"run1","hypothesisId":"H1"})+"\n")
        # #endregion
        
        return user
    except ValueError:
        # #region agent log
        with open('/home/eniac/Desktop/NFT-TICKETING/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"location":"auth_middleware.py:76","message":"get_current_user ValueError","data":{"user_id":user_id},"timestamp":int(time.time()*1000),"sessionId":"debug-session","runId":"run1","hypothesisId":"H1"})+"\n")
        # #endregion
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID"
        )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: Client = Depends(get_supabase_admin)
) -> Optional[dict]:
    """Get current user if authenticated, otherwise return None."""
    if credentials is None:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


def require_role(required_role: str):
    """Dependency factory to require a specific role."""
    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "").upper()
        required = required_role.upper()
        
        if user_role != required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_role} role"
            )
        
        return user
    
    return role_checker

