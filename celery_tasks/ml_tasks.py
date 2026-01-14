"""
ML-related Celery tasks for scheduled calculations.
"""
from celery import Task
from celery_app import celery_app
from database import get_supabase_admin
from supabase import Client
import logging
from typing import Dict, Any, List
from datetime import datetime
import sys
from pathlib import Path

# Add services path for PoW/PoS calculator
services_path = Path(__file__).parent.parent / "services"
if str(services_path) not in sys.path:
    sys.path.insert(0, str(services_path))

logger = logging.getLogger(__name__)


class DatabaseTask(Task):
    """Base task class with database connection."""
    _db: Client = None

    @property
    def db(self):
        if self._db is None:
            self._db = get_supabase_admin()
        return self._db


@celery_app.task(base=DatabaseTask, bind=True, name="celery_tasks.ml_tasks.calculate_all_pow_pos_scores")
def calculate_all_pow_pos_scores(self: DatabaseTask) -> Dict[str, Any]:
    """
    Calculate PoW/PoS scores for all active wallets.
    
    This task:
    1. Retrieves all active wallets
    2. Calculates PoW and PoS scores
    3. Saves scores to database
    4. Logs results
    
    Runs: Daily at 2 AM UTC
    """
    try:
        logger.info("Starting PoW/PoS score calculation for all wallets")
        
        db = self.db
        from pow_pos_calculator import PoWPoSCalculator
        
        calculator = PoWPoSCalculator(db)
        
        # Get all active wallets (wallets with transactions in last 90 days)
        from datetime import timedelta
        ninety_days_ago = (datetime.now() - timedelta(days=90)).isoformat()
        
        wallets_response = db.table("transactions").select(
            "wallet_address"
        ).gte("created_at", ninety_days_ago).execute()
        
        # Get unique wallet addresses
        unique_wallets = set()
        if wallets_response.data:
            for txn in wallets_response.data:
                if txn.get("wallet_address"):
                    unique_wallets.add(txn["wallet_address"].lower())
        
        wallets_list = list(unique_wallets)
        processed_count = 0
        error_count = 0
        
        logger.info(f"Found {len(wallets_list)} active wallets to process")
        
        # Calculate scores for each wallet
        for wallet_address in wallets_list:
            try:
                # Get wallet balance (would need Web3 integration for real balance)
                wallet_balance_eth = 0.0  # Placeholder - would fetch from blockchain
                
                # Calculate scores
                scores = calculator.calculate_all_scores(wallet_address, wallet_balance_eth)
                
                # Save scores
                calculator.save_scores(scores)
                
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Error calculating scores for wallet {wallet_address}: {e}")
                error_count += 1
                continue
        
        result = {
            "success": True,
            "total_wallets": len(wallets_list),
            "processed_count": processed_count,
            "error_count": error_count,
            "timestamp": datetime.now().isoformat(),
            "task_id": self.request.id
        }
        
        logger.info(f"PoW/PoS calculation completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error calculating PoW/PoS scores: {e}", exc_info=True)
        raise
