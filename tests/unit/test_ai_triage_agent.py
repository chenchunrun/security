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
Unit tests for AI Triage Agent Service.
Tests LLM-based alert analysis, prompt engineering, and multi-model routing.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
import json


class TestTriagePromptEngineering:
    """Test triage prompt generation and engineering."""

    def test_build_basic_triage_prompt(self):
        """Test building basic triage prompt."""
        from services.ai_triage_agent.main import build_triage_prompt
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-001",
            alert_type="malware",
            severity="high",
            title="Malware Detected",
            description="EICAR test file found",
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            file_hash="44d88612fea8a8f36de82e1278abb02f"
        )

        prompt = build_triage_prompt(alert)

        assert "ALT-001" in prompt
        assert "malware" in prompt
        assert "high" in prompt
        assert "192.168.1.100" in prompt
        assert "44d88612fea8a8f36de82e1278abb02f" in prompt

    def test_build_prompt_with_context(self):
        """Test building prompt with enriched context."""
        from services.ai_triage_agent.main import build_triage_prompt
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-002",
            alert_type="phishing",
            severity="critical",
            title="Phishing Email",
            description="Suspicious email with attachment"
        )

        enrichment = {
            "asset_criticality": "high",
            "threat_intel": [
                {"source": "virustotal", "detected": True, "positives": 5}
            ],
            "similar_alerts": [
                {"alert_id": "ALT-001", "similarity": 0.85, "risk_level": "high"}
            ],
            "network_context": {
                "subnet": "DMZ",
                "vlans": ["100", "200"]
            }
        }

        prompt = build_triage_prompt(alert, enrichment)

        assert "Critical Asset" in prompt
        assert "VirusTotal" in prompt
        assert "ALT-001" in prompt
        assert "DMZ" in prompt

    def test_build_prompt_with_iocs(self):
        """Test prompt includes IOCs."""
        from services.ai_triage_agent.main import build_triage_prompt
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-003",
            alert_type="malware",
            severity="high",
            title="Malware with IOCs",
            description="Multiple IOCs detected",
            source_ip="8.8.8.8",
            file_hash="abc123def456",
            domain="malicious.example.com",
            url="http://malicious.example.com/payload"
        )

        prompt = build_triage_prompt(alert)

        assert "8.8.8.8" in prompt
        assert "abc123def456" in prompt
        assert "malicious.example.com" in prompt

    def test_structured_output_prompt(self):
        """Test prompt for structured JSON output."""
        from services.ai_triage_agent.main import build_triage_prompt
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-004",
            alert_type="brute_force",
            severity="medium",
            title="SSH Brute Force",
            description="Multiple failed login attempts"
        )

        prompt = build_triage_prompt(alert)

        assert "JSON" in prompt
        assert "risk_level" in prompt
        assert "confidence" in prompt
        assert "recommendations" in prompt


class TestLLMModelRouting:
    """Test intelligent LLM model routing."""

    def test_route_by_complexity_high(self):
        """Test routing to DeepSeek for high complexity."""
        from services.ai_triage_agent.main import route_llm_model

        alert_data = {
            "alert_type": "malware",
            "description": "Complex multi-stage attack with multiple IOCs and known APT patterns",
            "severity": "critical",
            "iocs_count": 10
        }

        model = route_llm_model(alert_data)

        assert model == "deepseek-v3"

    def test_route_by_complexity_low(self):
        """Test routing to Qwen for low complexity."""
        from services.ai_triage_agent.main import route_llm_model

        alert_data = {
            "alert_type": "anomaly",
            "description": "Simple login at unusual time",
            "severity": "low",
            "iocs_count": 0
        }

        model = route_llm_model(alert_data)

        assert model == "qwen-plus"

    def test_route_by_alert_type_malware(self):
        """Test malware alerts route to high-capability model."""
        from services.ai_triage_agent.main import route_llm_model

        alert_data = {
            "alert_type": "malware",
            "description": "Suspicious file",
            "severity": "high"
        }

        model = route_llm_model(alert_data)

        assert model in ["deepseek-v3", "qwen-plus"]

    def test_route_with_similarity_context(self):
        """Test routing considers similar alerts count."""
        from services.ai_triage_agent.main import route_llm_model

        alert_data = {
            "alert_type": "phishing",
            "description": "Phishing email",
            "severity": "medium",
            "similar_alerts_count": 5
        }

        model = route_llm_model(alert_data)

        assert model is not None


class TestTriageAnalysis:
    """Test AI triage analysis logic."""

    @pytest.mark.asyncio
    async def test_triage_alert_success(self):
        """Test successful alert triage."""
        from services.ai_triage_agent.main import triage_alert
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-001",
            alert_type="malware",
            severity="high",
            title="Test Malware",
            description="Test"
        )

        with patch('services.ai_triage_agent.main.query_llm') as mock_llm, \
             patch('services.ai_triage_agent.main.query_similar_alerts') as mock_similar:

            mock_llm.return_value = {
                "risk_level": "critical",
                "confidence": 95,
                "recommendations": ["Isolate host", "Block hash"],
                "indicators": ["C2 server communication"]
            }

            mock_similar.return_value = {
                "results": []
            }

            result = await triage_alert(alert)

            assert result["risk_level"] == "critical"
            assert result["confidence"] == 95
            assert len(result["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_triage_with_threat_intel(self):
        """Test triage with threat intelligence enrichment."""
        from services.ai_triage_agent.main import triage_alert
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-002",
            alert_type="malware",
            severity="high",
            source_ip="8.8.8.8",
            file_hash="44d88612fea8a8f36de82e1278abb02f"
        )

        with patch('services.ai_triage_agent.main.query_llm') as mock_llm, \
             patch('services.ai_triage_agent.main.query_threat_intel') as mock_ti, \
             patch('services.ai_triage_agent.main.query_similar_alerts') as mock_similar:

            mock_ti.return_value = {
                "sources": [
                    {"source": "virustotal", "detected": True, "positives": 5}
                ],
                "aggregate_score": 80
            }

            mock_llm.return_value = {
                "risk_level": "critical",
                "confidence": 90,
                "recommendations": ["Quarantine"]
            }

            mock_similar.return_value = {"results": []}

            result = await triage_alert(alert)

            # Should incorporate threat intel into analysis
            assert result["confidence"] >= 90

    @pytest.mark.asyncio
    async def test_triage_llm_failure_fallback(self):
        """Test fallback when LLM call fails."""
        from services.ai_triage_agent.main import triage_alert
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-003",
            alert_type="anomaly",
            severity="medium",
            title="Test",
            description="Test"
        )

        with patch('services.ai_triage_agent.main.query_llm') as mock_llm, \
             patch('services.ai_triage_agent.main.query_similar_alerts') as mock_similar:

            mock_llm.side_effect = Exception("LLM API error")
            mock_similar.return_value = {"results": []}

            result = await triage_alert(alert)

            # Should fallback to rule-based triage
            assert "risk_level" in result
            assert "confidence" in result

    @pytest.mark.asyncio
    async def test_triage_with_similar_alerts(self):
        """Test triage incorporating similar historical alerts."""
        from services.ai_triage_agent.main import triage_alert
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-004",
            alert_type="phishing",
            severity="high",
            title="Phishing Email",
            description="Suspicious email"
        )

        with patch('services.ai_triage_agent.main.query_llm') as mock_llm, \
             patch('services.ai_triage_agent.main.query_similar_alerts') as mock_similar:

            mock_similar.return_value = {
                "results": [
                    {
                        "alert_id": "ALT-001",
                        "similarity_score": 0.92,
                        "risk_level": "critical",
                        "description": "Similar phishing attack"
                    }
                ]
            }

            mock_llm.return_value = {
                "risk_level": "high",
                "confidence": 85,
                "recommendations": ["Block sender", "Delete emails"]
            }

            result = await triage_alert(alert)

            # Should increase confidence based on similar alerts
            assert result["confidence"] >= 80


class TestTriageResultValidation:
    """Test triage result validation and post-processing."""

    def test_validate_risk_level(self):
        """Test risk level validation."""
        from services.ai_triage_agent.main import validate_triage_result

        valid_result = {
            "risk_level": "critical",
            "confidence": 95,
            "recommendations": ["Isolate"]
        }

        assert validate_triage_result(valid_result) is True

    def test_validate_invalid_risk_level(self):
        """Test invalid risk level is rejected."""
        from services.ai_triage_agent.main import validate_triage_result

        invalid_result = {
            "risk_level": "invalid_level",
            "confidence": 50
        }

        assert validate_triage_result(invalid_result) is False

    def test_validate_confidence_range(self):
        """Test confidence is in valid range."""
        from services.ai_triage_agent.main import validate_triage_result

        invalid_result = {
            "risk_level": "high",
            "confidence": 150  # Out of range
        }

        assert validate_triage_result(invalid_result) is False

    def test_normalize_triage_result(self):
        """Test normalizing triage result."""
        from services.ai_triage_agent.main import normalize_triage_result

        raw_result = {
            "risk_level": "CRITICAL",
            "confidence": 95.5,
            "recommendations": "Isolate host, Block hash",
            "indicators": ["C2", "beacon"]
        }

        normalized = normalize_triage_result(raw_result)

        assert normalized["risk_level"] == "critical"
        assert normalized["confidence"] == 95
        assert isinstance(normalized["recommendations"], list)
        assert len(normalized["recommendations"]) == 2


class TestMultiProviderIntegration:
    """Test integration with multiple LLM providers."""

    @pytest.mark.asyncio
    async def test_query_zhipu_ai(self):
        """Test querying Zhipu AI provider."""
        from services.ai_triage_agent.main import query_llm

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "risk_level": "high",
                            "confidence": 85
                        })
                    }
                }]
            }
            mock_post.return_value = mock_response

            result = await query_llm(
                model="glm-4",
                prompt="Test prompt",
                provider="zhipu"
            )

            assert "risk_level" in result

    @pytest.mark.asyncio
    async def test_query_deepseek(self):
        """Test querying DeepSeek provider."""
        from services.ai_triage_agent.main import query_llm

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "risk_level": "critical",
                            "confidence": 92
                        })
                    }
                }]
            }
            mock_post.return_value = mock_response

            result = await query_llm(
                model="deepseek-chat",
                prompt="Test prompt",
                provider="deepseek"
            )

            assert "risk_level" in result

    @pytest.mark.asyncio
    async def test_query_qwen(self):
        """Test querying Qwen provider."""
        from services.ai_triage_agent.main import query_llm

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "output": {
                    "text": json.dumps({
                        "risk_level": "medium",
                        "confidence": 75
                    })
                }
            }
            mock_post.return_value = mock_response

            result = await query_llm(
                model="qwen-plus",
                prompt="Test prompt",
                provider="qwen"
            )

            assert "risk_level" in result

    @pytest.mark.asyncio
    async def test_query_openai(self):
        """Test querying OpenAI provider."""
        from services.ai_triage_agent.main import query_llm

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "risk_level": "high",
                            "confidence": 88
                        })
                    }
                }]
            }
            mock_post.return_value = mock_response

            result = await query_llm(
                model="gpt-4",
                prompt="Test prompt",
                provider="openai"
            )

            assert "risk_level" in result


class TestTriageCaching:
    """Test triage result caching."""

    @pytest.mark.asyncio
    async def test_cache_triage_result(self):
        """Test caching triage results."""
        from services.ai_triage_agent.main import cache_triage_result

        alert_id = "ALT-001"
        triage_result = {
            "risk_level": "critical",
            "confidence": 95
        }

        with patch('services.ai_triage_agent.main.cache_manager') as mock_cache:
            await cache_triage_result(alert_id, triage_result)

            mock_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_retrieve_cached_triage(self):
        """Test retrieving cached triage results."""
        from services.ai_triage_agent.main import get_cached_triage

        alert_id = "ALT-001"

        with patch('services.ai_triage_agent.main.cache_manager') as mock_cache:
            mock_cache.get.return_value = {
                "risk_level": "critical",
                "confidence": 95
            }

            cached = await get_cached_triage(alert_id)

            assert cached is not None
            assert cached["risk_level"] == "critical"

    @pytest.mark.asyncio
    async def test_cache_miss(self):
        """Test cache miss returns None."""
        from services.ai_triage_agent.main import get_cached_triage

        with patch('services.ai_triage_agent.main.cache_manager') as mock_cache:
            mock_cache.get.return_value = None

            cached = await get_cached_triage("ALT-999")

            assert cached is None


class TestBatchTriage:
    """Test batch alert triage."""

    @pytest.mark.asyncio
    async def test_batch_triage_alerts(self):
        """Test triaging multiple alerts."""
        from services.ai_triage_agent.main import batch_triage_alerts
        from services.shared.models import SecurityAlert

        alerts = [
            SecurityAlert(
                alert_id=f"ALT-{i:03d}",
                alert_type="malware",
                severity="high",
                title=f"Alert {i}",
                description="Test"
            )
            for i in range(1, 6)
        ]

        with patch('services.ai_triage_agent.main.triage_alert') as mock_triage:
            mock_triage.return_value = {
                "risk_level": "high",
                "confidence": 85
            }

            results = await batch_triage_alerts(alerts)

            assert len(results) == 5
            assert all("risk_level" in r for r in results)

    @pytest.mark.asyncio
    async def test_batch_triage_with_errors(self):
        """Test batch triage with partial failures."""
        from services.ai_triage_agent.main import batch_triage_alerts
        from services.shared.models import SecurityAlert

        alerts = [
            SecurityAlert(
                alert_id=f"ALT-{i:03d}",
                alert_type="malware",
                severity="high",
                title=f"Alert {i}",
                description="Test"
            )
            for i in range(1, 4)
        ]

        call_count = 0

        async def mock_triage_with_error(alert):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise Exception("LLM error")
            return {"risk_level": "high", "confidence": 85}

        with patch('services.ai_triage_agent.main.triage_alert', side_effect=mock_triage_with_error):
            results = await batch_triage_alerts(alerts, continue_on_error=True)

            # Should complete with partial results
            assert len(results) == 3
            assert any("error" in r for r in results)


class TestTriageMetrics:
    """Test triage metrics and monitoring."""

    def test_record_triage_metric(self):
        """Test recording triage metrics."""
        from services.ai_triage_agent.main import record_triage_metric

        metric = {
            "alert_id": "ALT-001",
            "model": "deepseek-v3",
            "duration_ms": 1500,
            "risk_level": "critical",
            "confidence": 95
        }

        with patch('services.ai_triage_agent.main.metrics_logger') as mock_logger:
            record_triage_metric(metric)

            mock_logger.info.assert_called_once()

    def test_calculate_triage_latency(self):
        """Test calculating triage latency."""
        from services.ai_triage_agent.main import calculate_triage_latency
        from datetime import datetime, timedelta

        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=5)

        latency = calculate_triage_latency(start_time, end_time)

        assert latency == 5.0

    def test_track_model_usage(self):
        """Test tracking model usage statistics."""
        from services.ai_triage_agent.main import track_model_usage

        model_stats = track_model_usage("deepseek-v3")

        assert "model" in model_stats
        assert "usage_count" in model_stats
        assert model_stats["model"] == "deepseek-v3"


class TestTriageErrorHandling:
    """Test triage error handling."""

    @pytest.mark.asyncio
    async def test_llm_timeout_handling(self):
        """Test handling LLM timeout."""
        from services.ai_triage_agent.main import triage_alert
        from services.shared.models import SecurityAlert
        import httpx

        alert = SecurityAlert(
            alert_id="ALT-001",
            alert_type="malware",
            severity="high",
            title="Test",
            description="Test"
        )

        with patch('services.ai_triage_agent.main.query_llm') as mock_llm, \
             patch('services.ai_triage_agent.main.query_similar_alerts') as mock_similar:

            mock_llm.side_effect = httpx.TimeoutException("Request timeout")
            mock_similar.return_value = {"results": []}

            result = await triage_alert(alert)

            # Should fallback gracefully
            assert "risk_level" in result
            assert "error" in result or "fallback" in result.get("metadata", {})

    @pytest.mark.asyncio
    async def test_invalid_json_response(self):
        """Test handling invalid JSON from LLM."""
        from services.ai_triage_agent.main import triage_alert
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-001",
            alert_type="malware",
            severity="high",
            title="Test",
            description="Test"
        )

        with patch('services.ai_triage_agent.main.query_llm') as mock_llm, \
             patch('services.ai_triage_agent.main.query_similar_alerts') as mock_similar:

            mock_llm.return_value = "Invalid JSON response"
            mock_similar.return_value = {"results": []}

            result = await triage_alert(alert)

            # Should handle gracefully
            assert "risk_level" in result


class TestHumanReviewDetermination:
    """Test logic for determining human review requirement."""

    def test_critical_requires_review(self):
        """Test critical risk level requires human review."""
        from services.ai_triage_agent.main import requires_human_review

        triage_result = {
            "risk_level": "critical",
            "confidence": 95
        }

        assert requires_human_review(triage_result) is True

    def test_high_risk_requires_review(self):
        """Test high risk level requires human review."""
        from services.ai_triage_agent.main import requires_human_review

        triage_result = {
            "risk_level": "high",
            "confidence": 85
        }

        assert requires_human_review(triage_result) is True

    def test_medium_risk_no_review(self):
        """Test medium risk may not require review."""
        from services.ai_triage_agent.main import requires_human_review

        triage_result = {
            "risk_level": "medium",
            "confidence": 80
        }

        assert requires_human_review(triage_result) is False

    def test_low_confidence_requires_review(self):
        """Test low confidence requires review regardless of risk."""
        from services.ai_triage_agent.main import requires_human_review

        triage_result = {
            "risk_level": "medium",
            "confidence": 50  # Low confidence
        }

        assert requires_human_review(triage_result) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
