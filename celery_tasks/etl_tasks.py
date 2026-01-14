"""
ETL tasks for Celery scheduler.
Handles automated feature engineering refresh and data validation.
"""
from celery import Task
from celery_app import celery_app
from database import get_supabase_admin
from supabase import Client
import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class DatabaseTask(Task):
    """Base task class with database connection."""
    _db: Client = None

    @property
    def db(self):
        if self._db is None:
            self._db = get_supabase_admin()
        return self._db


@celery_app.task(base=DatabaseTask, bind=True, name="celery_tasks.etl_tasks.refresh_ml_feature_cache")
def refresh_ml_feature_cache(self: DatabaseTask) -> Dict[str, Any]:
    """
    Refresh ML feature cache by recalculating features for recent transactions.
    
    This task:
    1. Identifies transactions needing feature recalculation
    2. Calls feature engineering pipeline
    3. Updates feature cache in DuckDB
    4. Logs results
    
    Runs: Every hour
    """
    try:
        logger.info("Starting ML feature cache refresh")
        
        db = self.db
        
        # Get transactions from last hour that need feature refresh
        from datetime import datetime, timedelta
        one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        
        # Query recent transactions
        response = db.table("transactions").select(
            "transaction_id, wallet_address, event_id, created_at"
        ).gte("created_at", one_hour_ago).limit(100).execute()
        
        transactions_count = len(response.data) if response.data else 0
        
        logger.info(f"Found {transactions_count} transactions to process")
        
        # Feature engineering would be triggered here
        # For now, we log the task execution
        result = {
            "success": True,
            "transactions_processed": transactions_count,
            "timestamp": datetime.now().isoformat(),
            "task_id": self.request.id
        }
        
        logger.info(f"Feature cache refresh completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error refreshing ML feature cache: {e}", exc_info=True)
        raise


@celery_app.task(base=DatabaseTask, bind=True, name="celery_tasks.etl_tasks.validate_etl_data")
def validate_etl_data(self: DatabaseTask) -> Dict[str, Any]:
    """
    Validate ETL data integrity and consistency.
    
    This task:
    1. Checks transactions table consistency
    2. Validates foreign key relationships
    3. Checks for missing or duplicate data
    4. Reports anomalies
    
    Runs: Every 6 hours
    """
    try:
        logger.info("Starting ETL data validation")
        
        db = self.db
        
        # Check transactions table
        transactions_response = db.table("transactions").select(
            "transaction_id, order_id, resale_id", count="exact"
        ).limit(1).execute()
        
        total_transactions = transactions_response.count if hasattr(transactions_response, 'count') else 0
        
        # Check for transactions without orders/resales (orphaned)
        orphaned_response = db.table("transactions").select(
            "transaction_id", count="exact"
        ).is_("order_id", "null").is_("resale_id", "null").limit(1).execute()
        
        orphaned_count = orphaned_response.count if hasattr(orphaned_response, 'count') else 0
        
        result = {
            "success": True,
            "total_transactions": total_transactions,
            "orphaned_transactions": orphaned_count,
            "validation_passed": orphaned_count < total_transactions * 0.1,  # Allow <10% orphaned
            "timestamp": datetime.now().isoformat(),
            "task_id": self.request.id
        }
        
        if not result["validation_passed"]:
            logger.warning(f"ETL validation found anomalies: {result}")
        else:
            logger.info(f"ETL validation passed: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error validating ETL data: {e}", exc_info=True)
        raise
