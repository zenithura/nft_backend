"""
Pytest configuration and fixtures for backend tests.
"""
import pytest
import os
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from supabase import Client

# Set test environment variables
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "test-secret-key-for-testing-only"
os.environ["SUPABASE_URL"] = os.getenv("SUPABASE_URL", "https://test.supabase.co")
os.environ["SUPABASE_KEY"] = os.getenv("SUPABASE_KEY", "test-key")
os.environ["SUPABASE_SERVICE_KEY"] = os.getenv("SUPABASE_SERVICE_KEY", "test-service-key")


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    from main import app
    return TestClient(app)


@pytest.fixture
def mock_supabase_client():
    """Create a mock Supabase client."""
    mock_client = Mock(spec=Client)
    return mock_client


@pytest.fixture
def mock_db_response():
    """Create a mock database response."""
    class MockResponse:
        def __init__(self, data=None, count=0):
            self.data = data or []
            self.count = count
        
        def execute(self):
            return self
    
    return MockResponse


@pytest.fixture
def test_wallet_address():
    """Test wallet address for testing."""
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def test_event_data():
    """Test event data."""
    return {
        "title": "Test Event",
        "description": "Test Description",
        "venue": "Test Venue",
        "event_date": "2024-12-31T23:59:59Z",
        "ticket_price": 100.0,
        "total_tickets": 100
    }
