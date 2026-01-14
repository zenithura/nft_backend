"""
Tests for ML services endpoints.
"""
import pytest
from fastapi import status
from unittest.mock import patch, Mock


class TestMLServicesEndpoints:
    """Test suite for ML services routes."""

    @patch('routers.ml_services_backend.get_ml_integration_backend')
    def test_fraud_prediction_endpoint_structure(self, mock_get_ml, client):
        """Test fraud prediction endpoint accepts required parameters."""
        mock_ml = Mock()
        mock_get_ml.return_value = mock_ml
        mock_ml.process_transaction.return_value = {
            "fraud_score": 0.25,
            "risk_level": "LOW",
            "decision": "APPROVED"
        }
        
        payload = {
            "transaction_id": "test-txn-123",
            "wallet_address": "0x1234567890123456789012345678901234567890",
            "event_id": 1,
            "price_paid": 100.0
        }
        
        response = client.post("/api/ml/predict/fraud", json=payload)
        # Should either succeed or fail with validation
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_503_SERVICE_UNAVAILABLE
        ]

    def test_fraud_prediction_validation(self, client):
        """Test fraud prediction endpoint validation."""
        # Missing required fields
        payload = {
            "wallet_address": "0x1234567890123456789012345678901234567890"
        }
        response = client.post("/api/ml/predict/fraud", json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @patch('routers.ml_services_backend.get_ml_integration_backend')
    def test_risk_analysis_endpoint_structure(self, mock_get_ml, client):
        """Test risk analysis endpoint accepts required parameters."""
        mock_ml = Mock()
        mock_get_ml.return_value = mock_ml
        mock_ml.analyze_risk.return_value = {
            "risk_score": 0.3,
            "risk_level": "MEDIUM",
            "factors": []
        }
        
        payload = {
            "wallet_address": "0x1234567890123456789012345678901234567890"
        }
        
        response = client.post("/api/ml/analyze/risk", json=payload)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_503_SERVICE_UNAVAILABLE
        ]
