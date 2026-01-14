"""
Chatbot router for Gemini API integration.
Provides endpoints for chatbot health check and message sending.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import os
import logging

router = APIRouter(prefix="/chatbot", tags=["Chatbot"])

logger = logging.getLogger(__name__)

# Check if Gemini API key is available
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("API_KEY")
GEMINI_AVAILABLE = bool(GEMINI_API_KEY)


class ChatMessageRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None


class ChatMessageResponse(BaseModel):
    response: str
    session_id: str
    timestamp: str
    error: Optional[str] = None


@router.get("/health")
async def chatbot_health():
    """Check chatbot service health and Gemini API availability."""
    return {
        "status": "ok" if GEMINI_AVAILABLE else "unavailable",
        "gemini_available": GEMINI_AVAILABLE,
        "message": "Chatbot service is operational" if GEMINI_AVAILABLE else "Gemini API key not configured"
    }


@router.post("/send", response_model=ChatMessageResponse)
async def send_chat_message(request: ChatMessageRequest):
    """
    Send a message to the chatbot (Gemini API).
    
    Note: This is a stub implementation. Full Gemini integration requires
    the Gemini API key and proper setup. Returns a friendly fallback message.
    """
    if not GEMINI_AVAILABLE:
        # Return a friendly fallback response
        return ChatMessageResponse(
            response="I'm currently in setup mode. The chatbot feature requires Gemini API configuration. Please check backend environment variables.",
            session_id=request.session_id or "default",
            timestamp=datetime.utcnow().isoformat() + "Z",
            error="Gemini API key not configured"
        )
    
    # TODO: Implement actual Gemini API integration
    # For now, return a placeholder response
    logger.warning("Chatbot endpoint called but Gemini integration not fully implemented")
    return ChatMessageResponse(
        response="Thank you for your message! The chatbot is currently being set up. Please check back later.",
        session_id=request.session_id or "default",
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
