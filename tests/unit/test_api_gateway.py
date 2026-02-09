# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Unit tests for API Gateway Service.
Tests request routing, rate limiting, authentication, and service discovery.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import httpx


class TestRequestRouting:
    """Test API gateway request routing."""

    @pytest.mark.asyncio
    async def test_route_request_to_alert_ingestor(self):
        """Test routing alert ingestion requests."""
        from services.api_gateway.main import route_request

        request = {
            "path": "/api/v1/alerts",
            "method": "POST",
            "body": {"alert_type": "malware", "severity": "high"}
        }

        with patch('services.api_gateway.main.service_discovery') as mock_discovery, \
             patch('httpx.AsyncClient.post') as mock_post:

            mock_discovery.return_value = "http://alert-ingestor:8000"
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"alert_id": "ALT-001"}
            mock_post.return_value = mock_response

            response = await route_request(request)

            assert response["status_code"] == 201
            assert response["data"]["alert_id"] == "ALT-001"

    @pytest.mark.asyncio
    async def test_route_request_to_ai_triage(self):
        """Test routing AI triage requests."""
        from services.api_gateway.main import route_request

        request = {
            "path": "/api/v1/triage",
            "method": "POST",
            "body": {"alert_id": "ALT-001"}
        }

        with patch('services.api_gateway.main.service_discovery') as mock_discovery, \
             patch('httpx.AsyncClient.post') as mock_post:

            mock_discovery.return_value = "http://ai-triage-agent:8000"
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"risk_level": "critical"}
            mock_post.return_value = mock_response

            response = await route_request(request)

            assert response["status_code"] == 200

    @pytest.mark.asyncio
    async def test_route_unknown_path(self):
        """Test routing unknown path returns 404."""
        from services.api_gateway.main import route_request

        request = {
            "path": "/api/v1/unknown",
            "method": "GET"
        }

        response = await route_request(request)

        assert response["status_code"] == 404

    @pytest.mark.asyncio
    async def test_route_with_path_params(self):
        """Test routing with path parameters."""
        from services.api_gateway.main import route_request

        request = {
            "path": "/api/v1/alerts/ALT-001",
            "method": "GET",
            "path_params": {"alert_id": "ALT-001"}
        }

        with patch('services.api_gateway.main.service_discovery') as mock_discovery, \
             patch('httpx.AsyncClient.get') as mock_get:

            mock_discovery.return_value = "http://alert-ingestor:8000"
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"alert_id": "ALT-001"}
            mock_get.return_value = mock_response

            response = await route_request(request)

            assert response["status_code"] == 200


class TestRateLimiting:
    """Test rate limiting functionality."""

    @pytest.mark.asyncio
    async def test_rate_limit_within_quota(self):
        """Test request within rate limit quota."""
        from services.api_gateway.main import check_rate_limit

        user_id = "user-001"
        endpoint = "/api/v1/alerts"

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            mock_redis.get.return_value = "5"  # 5 requests so far
            mock_redis.incr.return_value = 6

            allowed = await check_rate_limit(user_id, endpoint, limit=100)

            assert allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        """Test request exceeds rate limit."""
        from services.api_gateway.main import check_rate_limit

        user_id = "user-001"
        endpoint = "/api/v1/alerts"

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            mock_redis.get.return_value = "100"  # At limit

            allowed = await check_rate_limit(user_id, endpoint, limit=100)

            assert allowed is False

    @pytest.mark.asyncio
    async def test_rate_limit_window_reset(self):
        """Test rate limit window resets after time window."""
        from services.api_gateway.main import check_rate_limit

        user_id = "user-001"
        endpoint = "/api/v1/alerts"

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            mock_redis.get.return_value = None  # No counter

            allowed = await check_rate_limit(user_id, endpoint, limit=100)

            assert allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_per_ip(self):
        """Test IP-based rate limiting."""
        from services.api_gateway.main import check_rate_limit_by_ip

        ip_address = "192.168.1.100"

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            mock_redis.get.return_value = "10"
            mock_redis.incr.return_value = 11

            allowed = await check_rate_limit_by_ip(ip_address, limit=1000)

            assert allowed is True


class TestAuthentication:
    """Test API gateway authentication."""

    @pytest.mark.asyncio
    async def test_authenticate_with_valid_token(self):
        """Test authentication with valid JWT token."""
        from services.api_gateway.main import authenticate_request

        token = "valid.jwt.token"

        with patch('services.api_gateway.main.validate_token') as mock_validate:
            mock_validate.return_value = {
                "user_id": "user-001",
                "username": "john.doe",
                "role": "analyst"
            }

            user = await authenticate_request(token)

            assert user is not None
            assert user["user_id"] == "user-001"

    @pytest.mark.asyncio
    async def test_authenticate_with_invalid_token(self):
        """Test authentication with invalid token."""
        from services.api_gateway.main import authenticate_request

        token = "invalid.jwt.token"

        with patch('services.api_gateway.main.validate_token') as mock_validate:
            mock_validate.return_value = None

            user = await authenticate_request(token)

            assert user is None

    @pytest.mark.asyncio
    async def test_authenticate_with_api_key(self):
        """Test authentication with API key."""
        from services.api_gateway.main import authenticate_with_api_key

        api_key = "sk-proj-abc123"

        with patch('services.api_gateway.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "user_id": "user-001",
                "key_active": True
            }

            user = await authenticate_with_api_key(api_key)

            assert user is not None

    @pytest.mark.asyncio
    async def test_authenticate_without_credentials(self):
        """Test authentication fails without credentials."""
        from services.api_gateway.main import authenticate_request

        request = {
            "headers": {}  # No Authorization header
        }

        result = await authenticate_request(request)

        assert result is None


class TestAuthorization:
    """Test API gateway authorization."""

    @pytest.mark.asyncio
    async def test_authorize_with_permission(self):
        """Test authorization with required permission."""
        from services.api_gateway.main import authorize_request

        user = {
            "user_id": "user-001",
            "role": "analyst",
            "permissions": ["alert.read", "alert.update"]
        }

        required_permission = "alert.read"

        authorized = await authorize_request(user, required_permission)

        assert authorized is True

    @pytest.mark.asyncio
    async def test_authorize_without_permission(self):
        """Test authorization fails without required permission."""
        from services.api_gateway.main import authorize_request

        user = {
            "user_id": "user-001",
            "role": "viewer",
            "permissions": ["alert.read"]
        }

        required_permission = "alert.delete"

        authorized = await authorize_request(user, required_permission)

        assert authorized is False

    @pytest.mark.asyncio
    async def test_authorize_admin_bypass(self):
        """Test admin bypasses permission checks."""
        from services.api_gateway.main import authorize_request

        user = {
            "user_id": "admin-001",
            "role": "admin",
            "permissions": []
        }

        authorized = await authorize_request(user, "any.permission")

        assert authorized is True


class TestServiceDiscovery:
    """Test service discovery functionality."""

    @pytest.mark.asyncio
    async def test_discover_service_by_name(self):
        """Test discovering service by name."""
        from services.api_gateway.main import service_discovery

        service_name = "alert-ingestor"

        with patch('services.api_gateway.main.consul_client') as mock_consul:
            mock_consul.health.service.return_value = [
                {
                    "Service": {
                        "Address": "alert-ingestor",
                        "Port": 8000
                    }
                }
            ]

            url = await service_discovery(service_name)

            assert url == "http://alert-ingestor:8000"

    @pytest.mark.asyncio
    async def test_discover_service_not_found(self):
        """Test service not found returns None."""
        from services.api_gateway.main import service_discovery

        service_name = "nonexistent-service"

        with patch('services.api_gateway.main.consul_client') as mock_consul:
            mock_consul.health.service.return_value = []

            url = await service_discovery(service_name)

            assert url is None

    @pytest.mark.asyncio
    async def test_discover_service_load_balancing(self):
        """Test load balancing across multiple instances."""
        from services.api_gateway.main import service_discovery

        service_name = "alert-ingestor"

        with patch('services.api_gateway.main.consul_client') as mock_consul:
            mock_consul.health.service.return_value = [
                {"Service": {"Address": "ingestor-1", "Port": 8000}},
                {"Service": {"Address": "ingestor-2", "Port": 8000}},
                {"Service": {"Address": "ingestor-3", "Port": 8000}}
            ]

            # Multiple calls should distribute
            urls = [await service_discovery(service_name) for _ in range(10)]

            # Should have used multiple instances
            unique_urls = set(urls)
            assert len(unique_urls) > 1


class TestRequestTransformation:
    """Test request transformation logic."""

    def test_add_correlation_id(self):
        """Test adding correlation ID to request."""
        from services.api_gateway.main import add_correlation_id

        request = {
            "path": "/api/v1/alerts",
            "method": "POST",
            "body": {}
        }

        transformed = add_correlation_id(request)

        assert "correlation_id" in transformed
        assert len(transformed["correlation_id"]) > 0

    def test_transform_response_format(self):
        """Test transforming response to standard format."""
        from services.api_gateway.main import transform_response

        service_response = {
            "status_code": 200,
            "data": {"alert_id": "ALT-001"},
            "headers": {"content-type": "application/json"}
        }

        transformed = transform_response(service_response)

        assert "success" in transformed
        assert "data" in transformed
        assert "timestamp" in transformed

    def test_add_timing_headers(self):
        """Test adding timing headers."""
        from services.api_gateway.main import add_timing_headers

        request = {
            "headers": {}
        }

        started_at = datetime.now() - timedelta(milliseconds=150)

        headers = add_timing_headers(request, started_at)

        assert "x-request-duration" in headers


class TestErrorHandling:
    """Test API gateway error handling."""

    @pytest.mark.asyncio
    async def test_handle_service_unavailable(self):
        """Test handling service unavailable error."""
        from services.api_gateway.main import handle_service_error

        error = httpx.ConnectError("Service unavailable")

        response = await handle_service_error(error)

        assert response["status_code"] == 503
        assert "error" in response["data"]

    @pytest.mark.asyncio
    async def test_handle_service_timeout(self):
        """Test handling service timeout."""
        from services.api_gateway.main import handle_service_error

        error = httpx.TimeoutException("Request timeout")

        response = await handle_service_error(error)

        assert response["status_code"] == 504

    @pytest.mark.asyncio
    async def test_handle_service_error(self):
        """Test handling service error."""
        from services.api_gateway.main import handle_service_error

        error = httpx.HTTPStatusError(
            "Server error",
            request=Mock(),
            response=Mock(status_code=500)
        )

        response = await handle_service_error(error)

        assert response["status_code"] >= 500


class TestCaching:
    """Test API gateway caching."""

    @pytest.mark.asyncio
    async def test_cache_get_response(self):
        """Test getting cached response."""
        from services.api_gateway.main import get_cached_response

        cache_key = "GET:/api/v1/alerts/ALT-001"

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            mock_redis.get.return_value = '{"alert_id":"ALT-001"}'

            cached = await get_cached_response(cache_key)

            assert cached is not None
            assert cached["alert_id"] == "ALT-001"

    @pytest.mark.asyncio
    async def test_cache_set_response(self):
        """Test caching response."""
        from services.api_gateway.main import cache_response

        cache_key = "GET:/api/v1/alerts/ALT-001"
        response = {"alert_id": "ALT-001"}

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            await cache_response(cache_key, response, ttl=60)

            mock_redis.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_invalidate(self):
        """Test cache invalidation."""
        from services.api_gateway.main import invalidate_cache

        pattern = "/api/v1/alerts/*"

        with patch('services.api_gateway.main.redis_client') as mock_redis:
            await invalidate_cache(pattern)

            mock_redis.delete.assert_called()


class TestMetrics:
    """Test API gateway metrics."""

    @pytest.mark.asyncio
    async def test_record_request_metric(self):
        """Test recording request metrics."""
        from services.api_gateway.main import record_request_metric

        metric = {
            "endpoint": "/api/v1/alerts",
            "method": "POST",
            "status_code": 201,
            "duration_ms": 45,
            "user_id": "user-001"
        }

        with patch('services.api_gateway.main.metrics_logger') as mock_logger:
            await record_request_metric(metric)

            mock_logger.info.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_error_metric(self):
        """Test recording error metrics."""
        from services.api_gateway.main import record_error_metric

        error = {
            "error_type": "service_unavailable",
            "endpoint": "/api/v1/triage",
            "message": "AI triage service unavailable"
        }

        with patch('services.api_gateway.main.metrics_logger') as mock_logger:
            await record_error_metric(error)

            mock_logger.error.assert_called_once()


class TestCORS:
    """Test CORS handling."""

    def test_add_cors_headers(self):
        """Test adding CORS headers."""
        from services.api_gateway.main import add_cors_headers

        request = {
            "headers": {"origin": "https://example.com"}
        }

        response = {
            "headers": {}
        }

        with patch('services.api_gateway.main.CORS_ORIGINS', ["https://example.com"]):
            headers = add_cors_headers(request, response)

            assert "access-control-allow-origin" in headers
            assert headers["access-control-allow-origin"] == "https://example.com"

    def test_preflight_request(self):
        """Test handling CORS preflight request."""
        from services.api_gateway.main import handle_preflight_request

        request = {
            "method": "OPTIONS",
            "headers": {
                "origin": "https://example.com",
                "access-control-request-method": "POST"
            }
        }

        response = handle_preflight_request(request)

        assert response["status_code"] == 204
        assert "access-control-allow-methods" in response["headers"]


class TestAPIVersioning:
    """Test API versioning."""

    def test_parse_api_version(self):
        """Test parsing API version from path."""
        from services.api_gateway.main import parse_api_version

        version = parse_api_version("/api/v1/alerts")

        assert version == "v1"

    def test_route_to_correct_version(self):
        """Test routing to correct API version."""
        from services.api_gateway.main import route_to_version

        request = {
            "path": "/api/v2/alerts",
            "api_version": "v2"
        }

        with patch('services.api_gateway.main.service_discovery') as mock_discovery:
            mock_discovery.return_value = "http://alert-ingestor-v2:8000"

            url = route_to_version(request)

            assert "v2" in url or "alert-ingestor" in url


class TestRequestBodyValidation:
    """Test request body validation."""

    @pytest.mark.asyncio
    async def test_validate_json_body(self):
        """Test validating JSON request body."""
        from services.api_gateway.main import validate_request_body

        schema = {
            "type": "object",
            "properties": {
                "alert_type": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
            },
            "required": ["alert_type", "severity"]
        }

        body = {
            "alert_type": "malware",
            "severity": "high"
        }

        valid, errors = await validate_request_body(body, schema)

        assert valid is True
        assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_validate_invalid_body(self):
        """Test validation fails for invalid body."""
        from services.api_gateway.main import validate_request_body

        schema = {
            "type": "object",
            "properties": {
                "alert_type": {"type": "string"},
                "severity": {"type": "string"}
            },
            "required": ["alert_type", "severity"]
        }

        body = {
            "alert_type": "malware"
            # Missing severity
        }

        valid, errors = await validate_request_body(body, schema)

        assert valid is False
        assert len(errors) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
