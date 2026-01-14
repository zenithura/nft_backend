"""Wallet connection router for Web3 wallet syncing."""
from fastapi import APIRouter, HTTPException, Depends
from supabase import Client
from database import get_supabase_admin
from models import WalletAuthRequest
from typing import Optional

router = APIRouter(prefix="/wallet", tags=["Wallet"])


@router.post("/connect")
async def connect_wallet(
    wallet_data: WalletAuthRequest,
    db: Client = Depends(get_supabase_admin)
):
    """
    Connect wallet and optionally create/update user record.
    This is optional - wallet connection works without this endpoint.
    
    Supports multi-chain wallets (MetaMask, Binance Wallet).
    """
    try:
        address = wallet_data.address.lower()
        provider = getattr(wallet_data, 'provider', None)
        chain_id = getattr(wallet_data, 'chain_id', None)
        
        # Check if user exists with this wallet address
        user_response = db.table("users").select("*").eq("wallet_address", address).execute()
        
        # Update or create wallet record if needed
        wallet_response = db.table("wallets").select("*").eq("address", address).execute()
        
        wallet_update_data = {
            "address": address,
            "last_activity": "now()"
        }
        
        if wallet_response.data:
            # Update existing wallet
            db.table("wallets").update(wallet_update_data).eq("address", address).execute()
        else:
            # Create new wallet record
            wallet_update_data["created_at"] = "now()"
            db.table("wallets").insert(wallet_update_data).execute()
        
        if user_response.data:
            # User exists, return success
            return {
                "success": True,
                "message": "Wallet connected",
                "user": user_response.data[0],
                "provider": provider,
                "chain_id": chain_id
            }
        else:
            # User doesn't exist, but that's okay - wallet connection still works
            return {
                "success": True,
                "message": "Wallet connected (no user record found)",
                "address": address,
                "provider": provider,
                "chain_id": chain_id
            }
    
    except Exception as e:
        # Don't fail - wallet connection should work even if backend fails
        return {
            "success": True,
            "message": "Wallet connected (backend sync skipped)",
            "error": str(e)
        }

