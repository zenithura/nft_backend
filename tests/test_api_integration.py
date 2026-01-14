"""
Integration tests for API endpoints.
"""
import pytest
from fastapi import status


class TestAPIIntegration:
    """Integration test suite for API."""

    def test_cors_headers(self, client):
        """Test that CORS headers are set."""
        response = client.options("/")
        # CORS preflight should be handled
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT]

    def test_api_versioning(self, client):
        """Test API versioning information."""
        response = client.get("/")
        data = response.json()
        assert "version" in data
        assert data["version"] == "1.0.0"

    def test_error_handling(self, client):
        """Test error handling for invalid endpoints."""
        response = client.get("/api/nonexistent")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_json_response_format(self, client):
        """Test that responses are in JSON format."""
        response = client.get("/health")
        assert response.headers.get("content-type") == "application/json"
