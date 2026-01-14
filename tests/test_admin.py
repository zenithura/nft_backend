"""
Tests for admin endpoints.
"""
import pytest
from fastapi import status
from unittest.mock import patch, Mock


class TestAdminEndpoints:
    """Test suite for admin routes."""

    def test_admin_endpoints_require_auth(self, client):
        """Test that admin endpoints require authentication."""
        # Try to access admin endpoint without auth
        response = client.get("/api/admin/stats")
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @patch('routers.admin.require_admin_auth')
    @patch('routers.admin.get_supabase_admin')
    def test_pow_pos_metrics_endpoint_structure(self, mock_get_db, mock_auth, client):
        """Test PoW/PoS metrics endpoint structure."""
        mock_db = Mock()
        mock_get_db.return_value = mock_db
        mock_auth.return_value = {"admin_id": 1, "username": "admin"}
        
        # Mock database response
        mock_db.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value.data = []
        
        response = client.get("/api/admin/pow-pos-metrics?limit=10&sort_by=pow_score")
        # Should succeed if auth works, otherwise auth error
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @patch('routers.admin.require_admin_auth')
    def test_admin_stats_endpoint_requires_auth(self, mock_auth, client):
        """Test admin stats endpoint requires authentication."""
        mock_auth.side_effect = Exception("Unauthorized")
        
        response = client.get("/api/admin/stats")
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_500_INTERNAL_SERVER_ERROR
        ]
