"""
Celery application for ETL scheduling and background tasks.
Configured for automated feature engineering refresh and ML data pipeline.
"""
from celery import Celery
from celery.schedules import crontab
import os
from dotenv import load_dotenv

load_dotenv()

# Redis configuration (use Redis for broker and result backend)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
celery_app = Celery(
    "nft_ticketing",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "celery_tasks.etl_tasks",
        "celery_tasks.ml_tasks"
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes max per task
    task_soft_time_limit=25 * 60,  # 25 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Periodic task schedule
celery_app.conf.beat_schedule = {
    # Refresh ML feature cache every 1 hour
    "refresh-ml-feature-cache": {
        "task": "celery_tasks.etl_tasks.refresh_ml_feature_cache",
        "schedule": crontab(minute=0),  # Every hour at :00
        "options": {"expires": 3600}  # Expire after 1 hour if not executed
    },
    
    # Calculate PoW/PoS scores daily at 2 AM UTC
    "calculate-pow-pos-scores": {
        "task": "celery_tasks.ml_tasks.calculate_all_pow_pos_scores",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        "options": {"expires": 3600 * 12}  # Expire after 12 hours
    },
    
    # Run ETL data validation every 6 hours
    "validate-etl-data": {
        "task": "celery_tasks.etl_tasks.validate_etl_data",
        "schedule": crontab(minute=0, hour="*/6"),  # Every 6 hours
        "options": {"expires": 3600 * 3}
    },
}

if __name__ == "__main__":
    celery_app.start()
