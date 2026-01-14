"""
PoW/PoS Score Calculator Service
Computes Proof of Work and Proof of Stake scores for users.
"""

from typing import Dict, Optional
from datetime import datetime
from supabase import Client


class PoWPoSCalculator:
    """Calculate Proof of Work and Proof of Stake scores."""
    
    # PoW weights
    POW_TICKET_PURCHASE_WEIGHT = 10
    POW_EVENT_ATTENDANCE_WEIGHT = 5
    POW_MARKETPLACE_WEIGHT = 3
    POW_REFERRAL_WEIGHT = 2
    
    # PoS weights
    POS_NFT_TICKET_WEIGHT = 50
    POS_BALANCE_WEIGHT = 100  # per ETH
    POS_ACTIVITY_WEIGHT = 0.1  # per day active
    
    def __init__(self, db: Client):
        self.db = db
    
    def calculate_pow_score(self, wallet_address: str) -> Dict:
        """
        Calculate Proof of Work score based on activity.
        
        Formula:
        PoW = (tickets_purchased × 10) + (events_attended × 5) + 
              (marketplace_txns × 3) + (referrals × 2)
        """
        wallet_address_lower = wallet_address.lower()
        
        # Get wallet_id
        wallet_response = self.db.table("wallets").select("wallet_id").eq(
            "address", wallet_address_lower
        ).limit(1).execute()
        
        wallet_id = None
        if wallet_response.data:
            wallet_id = wallet_response.data[0].get("wallet_id")
        
        if not wallet_id:
            # Return zero scores for non-existent wallet
            return {
                'pow_score': 0.0,
                'pow_tickets_purchased': 0,
                'pow_events_attended': 0,
                'pow_marketplace_txns': 0,
                'pow_referrals': 0,
                'pow_last_activity_date': None
            }
        
        # Count tickets purchased (owned by this wallet)
        tickets_response = self.db.table("tickets").select(
            "ticket_id", count="exact"
        ).eq("owner_wallet_id", wallet_id).execute()
        
        tickets_purchased = tickets_response.count if hasattr(tickets_response, 'count') else len(tickets_response.data or [])
        
        # Count distinct events attended
        tickets_data = self.db.table("tickets").select(
            "event_id"
        ).eq("owner_wallet_id", wallet_id).execute()
        
        distinct_events = set(
            t.get("event_id") for t in (tickets_data.data or [])
            if t.get("event_id")
        )
        events_attended = len(distinct_events)
        
        # Count marketplace transactions (as seller)
        resales_response = self.db.table("resales").select(
            "resale_id", count="exact"
        ).eq("seller_wallet_id", wallet_id).in_("status", ["SOLD", "LISTED"]).execute()
        
        marketplace_txns = resales_response.count if hasattr(resales_response, 'count') else len(resales_response.data or [])
        
        # Count referrals (simplified - would need referral table)
        referrals = 0  # TODO: Implement referral tracking
        
        # Get last activity date
        orders_response = self.db.table("orders").select(
            "created_at"
        ).eq("buyer_wallet_id", wallet_id).order("created_at", desc=True).limit(1).execute()
        
        last_activity_date = None
        if orders_response.data:
            last_activity_date = orders_response.data[0].get("created_at")
        
        # Calculate PoW score
        pow_score = (
            tickets_purchased * self.POW_TICKET_PURCHASE_WEIGHT +
            events_attended * self.POW_EVENT_ATTENDANCE_WEIGHT +
            marketplace_txns * self.POW_MARKETPLACE_WEIGHT +
            referrals * self.POW_REFERRAL_WEIGHT
        )
        
        return {
            'pow_score': float(pow_score),
            'pow_tickets_purchased': tickets_purchased,
            'pow_events_attended': events_attended,
            'pow_marketplace_txns': marketplace_txns,
            'pow_referrals': referrals,
            'pow_last_activity_date': last_activity_date
        }
    
    def calculate_pos_score(self, wallet_address: str, wallet_balance_eth: float = 0.0) -> Dict:
        """
        Calculate Proof of Stake score based on economic stake.
        
        Formula:
        PoS = (nft_tickets_held × 50) + (wallet_balance_eth × 100) + (days_active × 0.1)
        """
        wallet_address_lower = wallet_address.lower()
        
        # Get wallet_id
        wallet_response = self.db.table("wallets").select("wallet_id").eq(
            "address", wallet_address_lower
        ).limit(1).execute()
        
        wallet_id = None
        if wallet_response.data:
            wallet_id = wallet_response.data[0].get("wallet_id")
        
        if not wallet_id:
            return {
                'pos_score': 0.0,
                'pos_nft_tickets_held': 0,
                'pos_wallet_balance_eth': 0.0,
                'pos_days_active': 0,
                'pos_first_activity_date': None,
                'pos_last_update_date': None
            }
        
        # Count NFT tickets currently held
        tickets_response = self.db.table("tickets").select(
            "ticket_id", count="exact"
        ).eq("owner_wallet_id", wallet_id).eq("status", "ACTIVE").execute()
        
        nft_tickets_held = tickets_response.count if hasattr(tickets_response, 'count') else len(tickets_response.data or [])
        
        # Get wallet age (days active)
        orders_response = self.db.table("orders").select(
            "created_at"
        ).eq("buyer_wallet_id", wallet_id).order("created_at", desc=False).limit(1).execute()
        
        days_active = 0
        first_activity_date = None
        if orders_response.data:
            first_activity_date = orders_response.data[0].get("created_at")
            if first_activity_date:
                try:
                    first_dt = datetime.fromisoformat(str(first_activity_date).replace('Z', '+00:00'))
                    days_active = (datetime.now(first_dt.tzinfo) - first_dt).days
                except:
                    days_active = 0
        
        # Calculate PoS score
        pos_score = (
            nft_tickets_held * self.POS_NFT_TICKET_WEIGHT +
            wallet_balance_eth * self.POS_BALANCE_WEIGHT +
            days_active * self.POS_ACTIVITY_WEIGHT
        )
        
        return {
            'pos_score': float(pos_score),
            'pos_nft_tickets_held': nft_tickets_held,
            'pos_wallet_balance_eth': wallet_balance_eth,
            'pos_days_active': days_active,
            'pos_first_activity_date': first_activity_date,
            'pos_last_update_date': datetime.now().isoformat()
        }
    
    def calculate_all_scores(self, wallet_address: str, wallet_balance_eth: float = 0.0) -> Dict:
        """Calculate both PoW and PoS scores."""
        pow_data = self.calculate_pow_score(wallet_address)
        pos_data = self.calculate_pos_score(wallet_address, wallet_balance_eth)
        
        return {
            **pow_data,
            **pos_data,
            'wallet_address': wallet_address.lower(),
            'calculated_at': datetime.now().isoformat()
        }
    
    def save_scores(self, scores: Dict):
        """Save calculated scores to database."""
        # Get wallet_id
        wallet_response = self.db.table("wallets").select(
            "wallet_id"
        ).eq("address", scores['wallet_address']).limit(1).execute()
        
        wallet_id = None
        if wallet_response.data:
            wallet_id = wallet_response.data[0].get("wallet_id")
        
        # Insert score record
        self.db.table("user_pow_pos_scores").insert({
            'wallet_id': wallet_id,
            'wallet_address': scores['wallet_address'],
            'pow_score': scores['pow_score'],
            'pow_tickets_purchased': scores['pow_tickets_purchased'],
            'pow_events_attended': scores['pow_events_attended'],
            'pow_marketplace_txns': scores['pow_marketplace_txns'],
            'pow_referrals': scores['pow_referrals'],
            'pow_last_activity_date': scores.get('pow_last_activity_date'),
            'pos_score': scores['pos_score'],
            'pos_nft_tickets_held': scores['pos_nft_tickets_held'],
            'pos_wallet_balance_eth': scores['pos_wallet_balance_eth'],
            'pos_days_active': scores['pos_days_active'],
            'pos_first_activity_date': scores.get('pos_first_activity_date'),
            'pos_last_update_date': scores.get('pos_last_update_date'),
            'calculated_at': scores['calculated_at']
        }).execute()
