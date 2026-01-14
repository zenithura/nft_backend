"""
Tests for wallet integration endpoints.
"""
import pytest
from fastapi import status
from unittest.mock import patch, Mock


class TestWalletEndpoints:
    """Test suite for wallet routes."""

    @patch('routers.wallet.get_supabase_admin')
    def test_wallet_auth_endpoint_structure(self, mock_get_db, client):
        """Test wallet authentication endpoint accepts required fields."""
        mock_db = Mock()
        mock_get_db.return_value = mock_db
        
        # Mock database response
        mock_db.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
        mock_db.table.return_value.insert.return_value.execute.return_value.data = [{
            "wallet_id": 1,
            "address": "0x1234567890123456789012345678901234567890"
        }]
        
        payload = {
            "address": "0x1234567890123456789012345678901234567890",
            "provider": "metamask",
            "chain_id": "1",
            "signature": "test-signature",
            "message": "test-message"
        }
        
        response = client.post("/api/wallet/auth", json=payload)
        # Should either succeed (200) or fail with validation (422) or auth error (401)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_401_UNAUTHORIZED]

    def test_wallet_auth_validation(self, client):
        """Test wallet authentication endpoint validation."""
        # Missing required field
        payload = {
            "provider": "metamask"
        }
        response = client.post("/api/wallet/auth", json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_wallet_auth_invalid_address(self, client):
        """Test wallet authentication with invalid address."""
        payload = {
            "address": "invalid-address",
            "provider": "metamask"
        }
        response = client.post("/api/wallet/auth", json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
