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
Unit tests for Context Collector Service.
Tests asset context, network context, and user context collection.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta


class TestAssetContext:
    """Test asset context collection."""

    @pytest.mark.asyncio
    async def test_collect_asset_context_by_ip(self):
        """Test collecting asset context by IP address."""
        from services.context_collector.main import collect_asset_context

        alert_data = {
            "source_ip": "192.168.1.100"
        }

        with patch('services.context_collector.main.query_cmdb') as mock_cmdb:
            mock_cmdb.return_value = {
                "asset_id": "AST-001",
                "hostname": "web-server-01",
                "asset_type": "server",
                "os": "Ubuntu 22.04",
                "criticality": "high",
                "owner": "IT Operations",
                "location": "Data Center 1"
            }

            context = await collect_asset_context(alert_data)

            assert context["hostname"] == "web-server-01"
            assert context["criticality"] == "high"
            assert context["asset_type"] == "server"

    @pytest.mark.asyncio
    async def test_collect_asset_context_by_hostname(self):
        """Test collecting asset context by hostname."""
        from services.context_collector.main import collect_asset_context

        alert_data = {
            "hostname": "db-server-01"
        }

        with patch('services.context_collector.main.query_cmdb') as mock_cmdb:
            mock_cmdb.return_value = {
                "asset_id": "AST-002",
                "hostname": "db-server-01",
                "asset_type": "database",
                "os": "RHEL 8",
                "criticality": "critical",
                "owner": "Database Team"
            }

            context = await collect_asset_context(alert_data)

            assert context["asset_id"] == "AST-002"
            assert context["criticality"] == "critical"

    @pytest.mark.asyncio
    async def test_collect_asset_context_not_found(self):
        """Test handling asset not found."""
        from services.context_collector.main import collect_asset_context

        alert_data = {
            "source_ip": "10.0.0.999"
        }

        with patch('services.context_collector.main.query_cmdb') as mock_cmdb:
            mock_cmdb.return_value = None

            context = await collect_asset_context(alert_data)

            assert context is None or "error" in context

    @pytest.mark.asyncio
    async def test_collect_asset_software_inventory(self):
        """Test collecting software inventory for asset."""
        from services.context_collector.main import collect_software_inventory

        asset_id = "AST-001"

        with patch('services.context_collector.main.query_cmdb') as mock_cmdb:
            mock_cmdb.return_value = {
                "asset_id": asset_id,
                "software": [
                    {"name": "nginx", "version": "1.18.0"},
                    {"name": "python", "version": "3.10"},
                    {"name": "postgresql", "version": "14"}
                ]
            }

            inventory = await collect_software_inventory(asset_id)

            assert len(inventory["software"]) == 3
            assert any(s["name"] == "nginx" for s in inventory["software"])

    @pytest.mark.asyncio
    async def test_collect_asset_vulnerabilities(self):
        """Test collecting asset vulnerabilities."""
        from services.context_collector.main import collect_vulnerabilities

        asset_id = "AST-001"

        with patch('services.context_collector.main.query_vulnerability_db') as mock_vuln:
            mock_vuln.return_value = [
                {
                    "cve_id": "CVE-2023-1234",
                    "severity": "high",
                    "affected_software": "nginx",
                    "cvss_score": 8.5
                },
                {
                    "cve_id": "CVE-2023-5678",
                    "severity": "medium",
                    "affected_software": "python",
                    "cvss_score": 6.5
                }
            ]

            vulnerabilities = await collect_vulnerabilities(asset_id)

            assert len(vulnerabilities) == 2
            assert any(v["severity"] == "high" for v in vulnerabilities)


class TestNetworkContext:
    """Test network context collection."""

    @pytest.mark.asyncio
    async def test_collect_network_context(self):
        """Test collecting network context."""
        from services.context_collector.main import collect_network_context

        alert_data = {
            "source_ip": "192.168.1.100"
        }

        with patch('services.context_collector.main.query_network_db') as mock_network:
            mock_network.return_value = {
                "subnet": "192.168.1.0/24",
                "vlan": "100",
                "network_zone": "DMZ",
                "firewall_rules": ["allow-http", "allow-https"],
                "gateway": "192.168.1.1",
                "dns_servers": ["8.8.8.8", "8.8.4.4"]
            }

            context = await collect_network_context(alert_data)

            assert context["network_zone"] == "DMZ"
            assert context["vlan"] == "100"

    @pytest.mark.asyncio
    async def test_collect_geolocation(self):
        """Test collecting IP geolocation."""
        from services.context_collector.main import collect_geolocation

        ip = "8.8.8.8"

        with patch('services.context_collector.main.query_geoip') as mock_geo:
            mock_geo.return_value = {
                "country": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "region": "California",
                "latitude": 37.422,
                "longitude": -122.084,
                "isp": "Google LLC"
            }

            geo = await collect_geolocation(ip)

            assert geo["country"] == "United States"
            assert geo["city"] == "Mountain View"

    @pytest.mark.asyncio
    async def test_collect_network_connections(self):
        """Test collecting active network connections."""
        from services.context_collector.main import collect_network_connections

        asset_id = "AST-001"

        with patch('services.context_collector.main.query_asset_connections') as mock_conn:
            mock_conn.return_value = [
                {
                    "local_ip": "192.168.1.100",
                    "local_port": 443,
                    "remote_ip": "10.0.0.50",
                    "remote_port": 54321,
                    "protocol": "tcp",
                    "state": "ESTABLISHED"
                },
                {
                    "local_ip": "192.168.1.100",
                    "local_port": 22,
                    "remote_ip": "192.168.1.50",
                    "remote_port": 55432,
                    "protocol": "tcp",
                    "state": "ESTABLISHED"
                }
            ]

            connections = await collect_network_connections(asset_id)

            assert len(connections) == 2
            assert any(c["local_port"] == 443 for c in connections)

    @pytest.mark.asyncio
    async def test_collect_dns_history(self):
        """Test collecting DNS query history."""
        from services.context_collector.main import collect_dns_history

        hostname = "malicious.example.com"

        with patch('services.context_collector.main.query_dns_logs') as mock_dns:
            mock_dns.return_value = [
                {
                    "query": "malicious.example.com",
                    "query_type": "A",
                    "timestamp": datetime.now() - timedelta(hours=1),
                    "client_ip": "192.168.1.100",
                    "response": "1.2.3.4"
                }
            ]

            history = await collect_dns_history(hostname)

            assert len(history) == 1
            assert history[0]["query"] == hostname


class TestUserContext:
    """Test user context collection."""

    @pytest.mark.asyncio
    async def test_collect_user_context_by_username(self):
        """Test collecting user context by username."""
        from services.context_collector.main import collect_user_context

        alert_data = {
            "username": "john.doe"
        }

        with patch('services.context_collector.main.query_directory') as mock_dir:
            mock_dir.return_value = {
                "user_id": "USR-001",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "department": "Engineering",
                "title": "Software Engineer",
                "manager": "jane.smith",
                "location": "New York",
                "hire_date": "2020-01-15"
            }

            context = await collect_user_context(alert_data)

            assert context["email"] == "john.doe@example.com"
            assert context["department"] == "Engineering"

    @pytest.mark.asyncio
    async def test_collect_user_context_by_email(self):
        """Test collecting user context by email."""
        from services.context_collector.main import collect_user_context

        alert_data = {
            "email": "john.doe@example.com"
        }

        with patch('services.context_collector.main.query_directory') as mock_dir:
            mock_dir.return_value = {
                "user_id": "USR-001",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "department": "Engineering"
            }

            context = await collect_user_context(alert_data)

            assert context["user_id"] == "USR-001"

    @pytest.mark.asyncio
    async def test_collect_user_groups(self):
        """Test collecting user group memberships."""
        from services.context_collector.main import collect_user_groups

        user_id = "USR-001"

        with patch('services.context_collector.main.query_directory') as mock_dir:
            mock_dir.return_value = {
                "user_id": user_id,
                "groups": [
                    {"name": "Developers", "domain": "CORP"},
                    {"name": "DevOps", "domain": "CORP"},
                    {"name": "Admins", "domain": "LOCAL"}
                ]
            }

            groups = await collect_user_groups(user_id)

            assert len(groups) == 3
            assert any(g["name"] == "Developers" for g in groups)

    @pytest.mark.asyncio
    async def test_collect_user_login_history(self):
        """Test collecting user login history."""
        from services.context_collector.main import collect_login_history

        user_id = "USR-001"

        with patch('services.context_collector.main.query_auth_logs') as mock_logs:
            mock_logs.return_value = [
                {
                    "timestamp": datetime.now() - timedelta(hours=2),
                    "source_ip": "192.168.1.50",
                    "success": True,
                    "method": "password"
                },
                {
                    "timestamp": datetime.now() - timedelta(days=1),
                    "source_ip": "192.168.1.50",
                    "success": True,
                    "method": "password"
                }
            ]

            history = await collect_login_history(user_id, days=7)

            assert len(history) == 2
            assert all(h["success"] for h in history)

    @pytest.mark.asyncio
    async def test_collect_user_permissions(self):
        """Test collecting user permissions."""
        from services.context_collector.main import collect_user_permissions

        user_id = "USR-001"

        with patch('services.context_collector.main.query_directory') as mock_dir:
            mock_dir.return_value = {
                "user_id": user_id,
                "permissions": [
                    "file.read",
                    "file.write",
                    "server.ssh",
                    "database.query"
                ]
            }

            permissions = await collect_user_permissions(user_id)

            assert len(permissions) == 4
            assert "server.ssh" in permissions


class TestContextAggregation:
    """Test aggregating all context sources."""

    @pytest.mark.asyncio
    async def test_aggregate_full_context(self):
        """Test aggregating full context for alert."""
        from services.context_collector.main import aggregate_context

        alert_data = {
            "alert_id": "ALT-001",
            "source_ip": "192.168.1.100",
            "username": "john.doe",
            "hostname": "web-server-01"
        }

        with patch('services.context_collector.main.collect_asset_context') as mock_asset, \
             patch('services.context_collector.main.collect_network_context') as mock_network, \
             patch('services.context_collector.main.collect_user_context') as mock_user:

            mock_asset.return_value = {
                "asset_id": "AST-001",
                "criticality": "high"
            }

            mock_network.return_value = {
                "network_zone": "DMZ",
                "subnet": "192.168.1.0/24"
            }

            mock_user.return_value = {
                "user_id": "USR-001",
                "department": "Engineering"
            }

            context = await aggregate_context(alert_data)

            assert context["asset"]["criticality"] == "high"
            assert context["network"]["network_zone"] == "DMZ"
            assert context["user"]["department"] == "Engineering"

    @pytest.mark.asyncio
    async def test_aggregate_partial_context(self):
        """Test aggregating with partial context available."""
        from services.context_collector.main import aggregate_context

        alert_data = {
            "alert_id": "ALT-002",
            "source_ip": "10.0.0.50"
        }

        with patch('services.context_collector.main.collect_asset_context') as mock_asset, \
             patch('services.context_collector.main.collect_network_context') as mock_network, \
             patch('services.context_collector.main.collect_user_context') as mock_user:

            mock_asset.return_value = {"asset_id": "AST-002", "criticality": "medium"}
            mock_network.return_value = {"network_zone": "Internal"}
            mock_user.return_value = None  # No user context

            context = await aggregate_context(alert_data)

            assert context["asset"] is not None
            assert context["network"] is not None
            assert context["user"] is None


class TestContextCaching:
    """Test context caching."""

    @pytest.mark.asyncio
    async def test_cache_context_result(self):
        """Test caching context results."""
        from services.context_collector.main import cache_context

        key = "asset:192.168.1.100"
        data = {"hostname": "web-01", "criticality": "high"}

        with patch('services.context_collector.main.cache_manager') as mock_cache:
            await cache_context(key, data, ttl=3600)

            mock_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_retrieve_cached_context(self):
        """Test retrieving cached context."""
        from services.context_collector.main import get_cached_context

        key = "asset:192.168.1.100"

        with patch('services.context_collector.main.cache_manager') as mock_cache:
            mock_cache.get.return_value = {"hostname": "web-01"}

            cached = await get_cached_context(key)

            assert cached is not None
            assert cached["hostname"] == "web-01"

    @pytest.mark.asyncio
    async def test_context_cache_hit(self):
        """Test cache hit returns immediately."""
        from services.context_collector.main import collect_asset_context

        alert_data = {"source_ip": "192.168.1.100"}

        with patch('services.context_collector.main.get_cached_context') as mock_get:
            mock_get.return_value = {
                "asset_id": "AST-001",
                "hostname": "web-01",
                "cached": True
            }

            context = await collect_asset_context(alert_data)

            assert context["cached"] is True


class TestContextEnrichment:
    """Test context enrichment for alerts."""

    @pytest.mark.asyncio
    async def test_enrich_alert_with_context(self):
        """Test enriching alert with collected context."""
        from services.context_collector.main import enrich_alert_context

        alert = {
            "alert_id": "ALT-001",
            "source_ip": "192.168.1.100",
            "severity": "high"
        }

        context = {
            "asset": {"criticality": "high", "hostname": "web-01"},
            "network": {"network_zone": "DMZ"}
        }

        enriched = await enrich_alert_context(alert, context)

        assert enriched["asset_criticality"] == "high"
        assert enriched["hostname"] == "web-01"
        assert enriched["network_zone"] == "DMZ"

    @pytest.mark.asyncio
    async def test_calculate_asset_risk_multiplier(self):
        """Test calculating asset risk multiplier."""
        from services.context_collector.main import calculate_asset_risk_multiplier

        # Critical asset -> 2.0x multiplier
        multiplier = calculate_asset_risk_multiplier("critical")
        assert multiplier == 2.0

        # High asset -> 1.5x multiplier
        multiplier = calculate_asset_risk_multiplier("high")
        assert multiplier == 1.5

        # Low asset -> 1.0x multiplier
        multiplier = calculate_asset_risk_multiplier("low")
        assert multiplier == 1.0


class TestContextErrors:
    """Test context collection error handling."""

    @pytest.mark.asyncio
    async def test_cmdb_timeout(self):
        """Test handling CMDB timeout."""
        from services.context_collector.main import collect_asset_context
        import httpx

        alert_data = {"source_ip": "192.168.1.100"}

        with patch('services.context_collector.main.query_cmdb') as mock_cmdb:
            mock_cmdb.side_effect = httpx.TimeoutException("CMDB timeout")

            context = await collect_asset_context(alert_data)

            # Should handle gracefully
            assert context is None or "error" in context

    @pytest.mark.asyncio
    async def test_directory_service_unavailable(self):
        """Test handling directory service unavailable."""
        from services.context_collector.main import collect_user_context

        alert_data = {"username": "john.doe"}

        with patch('services.context_collector.main.query_directory') as mock_dir:
            mock_dir.side_effect = Exception("Directory service unavailable")

            context = await collect_user_context(alert_data)

            assert context is None or "error" in context

    @pytest.mark.asyncio
    async def test_partial_context_failure(self):
        """Test continuing with partial context on failure."""
        from services.context_collector.main import aggregate_context

        alert_data = {
            "alert_id": "ALT-001",
            "source_ip": "192.168.1.100",
            "username": "john.doe"
        }

        with patch('services.context_collector.main.collect_asset_context') as mock_asset, \
             patch('services.context_collector.main.collect_network_context') as mock_network, \
             patch('services.context_collector.main.collect_user_context') as mock_user:

            mock_asset.return_value = {"asset_id": "AST-001", "criticality": "high"}
            mock_network.return_value = {"network_zone": "DMZ"}
            mock_user.side_effect = Exception("User directory error")

            context = await aggregate_context(alert_data, continue_on_error=True)

            # Should return partial context
            assert context["asset"] is not None
            assert context["network"] is not None
            assert context.get("user") is None


class TestContextMetrics:
    """Test context collection metrics."""

    @pytest.mark.asyncio
    async def test_record_context_metric(self):
        """Test recording context collection metrics."""
        from services.context_collector.main import record_context_metric

        metric = {
            "context_type": "asset",
            "source": "cmdb",
            "duration_ms": 150,
            "cached": False
        }

        with patch('services.context_collector.main.metrics_logger') as mock_logger:
            await record_context_metric(metric)

            mock_logger.info.assert_called_once()

    def test_calculate_context_enrichment_rate(self):
        """Test calculating context enrichment rate."""
        from services.context_collector.main import calculate_enrichment_rate

        total_alerts = 100
        enriched_alerts = 85

        rate = calculate_enrichment_rate(total_alerts, enriched_alerts)

        assert rate == 0.85


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
