"""
Unit tests for Alert Ingestor service.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient


class TestAlertIngestorAPI:
    """Test Alert Ingestor API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from services.alert_ingestor.main import app
        return TestClient(app)

    @pytest.fixture
    def mock_publisher(self):
        """Mock message publisher."""
        with patch("services.alert_ingestor.main.MessagePublisher") as mock:
            publisher_instance = MagicMock()
            publisher_instance.connect = AsyncMock()
            publisher_instance.publish = AsyncMock()
            publisher_instance.close = AsyncMock()
            mock.return_value = publisher_instance
            yield publisher_instance

    @pytest.fixture
    def mock_db(self):
        """Mock database manager."""
        with patch("services.alert_ingestor.main.get_database_manager") as mock:
            db_instance = MagicMock()
            db_instance.initialize = AsyncMock()
            db_instance.close = AsyncMock()
            mock.return_value = db_instance
            yield db_instance

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "alert-ingestor"

    def test_ingest_alert_success(self, client, mock_publisher, mock_db):
        """Test successful alert ingestion."""
        alert_data = {
            "alert_id": "ALT-TEST-001",
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": "malware",
            "severity": "high",
            "description": "Test alert",
            "source_ip": "45.33.32.156",
            "target_ip": "10.0.0.50"
        }

        response = client.post("/api/v1/alerts", json=alert_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "ingestion_id" in data["data"]
        assert data["data"]["status"] == "queued"

        # Verify message was published
        mock_publisher.publish.assert_called_once()

    def test_ingest_alert_invalid_data(self, client):
        """Test alert ingestion with invalid data."""
        invalid_data = {
            "alert_id": "",  # Invalid: empty
            "timestamp": "invalid-date",  # Invalid format
            "alert_type": "invalid-type",
            "severity": "critical"
        }

        response = client.post("/api/v1/alerts", json=invalid_data)

        assert response.status_code == 422  # Validation error

    def test_ingest_batch_alerts(self, client, mock_publisher, mock_db):
        """Test batch alert ingestion."""
        batch_data = {
            "alerts": [
                {
                    "alert_id": f"ALT-BATCH-{i}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "alert_type": "malware",
                    "severity": "high",
                    "description": f"Batch alert {i}"
                }
                for i in range(3)
            ]
        }

        response = client.post("/api/v1/alerts/batch", json=batch_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "accepted" in data["data"]
        assert data["data"]["accepted"] == 3

    def test_get_alert_status(self, client):
        """Test getting alert status."""
        alert_id = "ALT-TEST-001"

        response = client.get(f"/api/v1/alerts/{alert_id}")

        # Should return status (may be 404 if not found in cache)
        assert response.status_code in [200, 404]


class TestAlertIngestorLogic:
    """Test Alert Ingestor business logic."""

    @pytest.mark.asyncio
    async def test_message_format(self, mock_publisher):
        """Test message is formatted correctly."""
        from services.alert_ingestor.main import create_alert_message
        from shared.models import SecurityAlert, AlertType, Severity

        alert = SecurityAlert(
            alert_id="ALT-MSG-TEST",
            timestamp=datetime.utcnow(),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="Test"
        )

        message = create_alert_message(alert)

        assert message["message_type"] == "alert.raw"
        assert "payload" in message
        assert message["payload"]["alert_id"] == "ALT-MSG-TEST"
        assert "timestamp" in message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
