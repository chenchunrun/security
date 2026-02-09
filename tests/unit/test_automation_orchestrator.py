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
Unit tests for Automation Orchestrator Service.
Tests SOAR playbook execution, actions, and rollback.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta


class TestPlaybookDefinitions:
    """Test SOAR playbook definitions."""

    def test_malware_containment_playbook_exists(self):
        """Test malware containment playbook is defined."""
        from services.automation_orchestrator.playbooks import MALWARE_CONTAINMENT_PLAYBOOK

        assert MALWARE_CONTAINMENT_PLAYBOOK is not None
        assert "playbook_id" in MALWARE_CONTAINMENT_PLAYBOOK
        assert "actions" in MALWARE_CONTAINMENT_PLAYBOOK
        assert len(MALWARE_CONTAINMENT_PLAYBOOK["actions"]) > 0

    def test_ransomware_response_playbook_exists(self):
        """Test ransomware response playbook is defined."""
        from services.automation_orchestrator.playbooks import RANSOMWARE_RESPONSE_PLAYBOOK

        assert RANSOMWARE_RESPONSE_PLAYBOOK is not None
        assert "trigger_conditions" in RANSOMWARE_RESPONSE_PLAYBOOK

    def test_phishing_containment_playbook_exists(self):
        """Test phishing email containment playbook is defined."""
        from services.automation_orchestrator.playbooks import PHISHING_EMAIL_CONTAINMENT_PLAYBOOK

        assert PHISHING_EMAIL_CONTAINMENT_PLAYBOOK is not None
        assert any("delete_email" in a["action"] for a in PHISHING_EMAIL_CONTAINMENT_PLAYBOOK["actions"])

    def test_all_playbooks_have_required_fields(self):
        """Test all playbooks have required fields."""
        from services.automation_orchestrator.playbooks import (
            MALWARE_CONTAINMENT_PLAYBOOK,
            RANSOMWARE_RESPONSE_PLAYBOOK,
            PHISHING_EMAIL_CONTAINMENT_PLAYBOOK,
            BRUTE_FORCE_RATE_LIMITING_PLAYBOOK,
            ACCOUNT_LOCKOUT_ENFORCEMENT_PLAYBOOK,
            DATA_EXFILTRATION_CONTAINMENT_PLAYBOOK
        )

        playbooks = [
            MALWARE_CONTAINMENT_PLAYBOOK,
            RANSOMWARE_RESPONSE_PLAYBOOK,
            PHISHING_EMAIL_CONTAINMENT_PLAYBOOK,
            BRUTE_FORCE_RATE_LIMITING_PLAYBOOK,
            ACCOUNT_LOCKOUT_ENFORCEMENT_PLAYBOOK,
            DATA_EXFILTRATION_CONTAINMENT_PLAYBOOK
        ]

        for playbook in playbooks:
            assert "playbook_id" in playbook
            assert "name" in playbook
            assert "actions" in playbook
            assert len(playbook["actions"]) > 0
            assert "rollback_actions" in playbook


class TestPlaybookTriggers:
    """Test playbook trigger conditions."""

    def test_malware_trigger_by_alert_type(self):
        """Test malware playbook triggers on malware alerts."""
        from services.automation_orchestrator.main import evaluate_playbook_trigger

        alert = {
            "alert_type": "malware",
            "risk_level": "critical",
            "confidence": 95
        }

        triggered = evaluate_playbook_trigger(
            alert,
            MALWARE_CONTAINMENT_PLAYBOOK["trigger_conditions"]
        )

        assert triggered is True

    def test_ransomware_trigger_by_keywords(self):
        """Test ransomware playbook triggers on ransomware keywords."""
        from services.automation_orchestrator.main import evaluate_playbook_trigger

        alert = {
            "alert_type": "malware",
            "title": "Ransomware detected - file encryption",
            "risk_level": "critical"
        }

        triggered = evaluate_playbook_trigger(
            alert,
            RANSOMWARE_RESPONSE_PLAYBOOK["trigger_conditions"]
        )

        assert triggered is True

    def test_phishing_trigger_by_alert_type(self):
        """Test phishing playbook triggers on phishing alerts."""
        from services.automation_orchestrator.main import evaluate_playbook_trigger

        alert = {
            "alert_type": "phishing",
            "risk_level": "high"
        }

        triggered = evaluate_playbook_trigger(
            alert,
            PHISHING_EMAIL_CONTAINMENT_PLAYBOOK["trigger_conditions"]
        )

        assert triggered is True

    def test_brute_force_trigger_by_failed_attempts(self):
        """Test brute force playbook triggers on failed attempts."""
        from services.automation_orchestrator.main import evaluate_playbook_trigger

        alert = {
            "alert_type": "brute_force",
            "failed_attempts": 15,
            "risk_level": "high"
        }

        triggered = evaluate_playbook_trigger(
            alert,
            BRUTE_FORCE_RATE_LIMITING_PLAYBOOK["trigger_conditions"]
        )

        assert triggered is True

    def test_playbook_not_triggered(self):
        """Test playbook doesn't trigger on mismatch."""
        from services.automation_orchestrator.main import evaluate_playbook_trigger

        alert = {
            "alert_type": "anomaly",
            "risk_level": "low"
        }

        triggered = evaluate_playbook_trigger(
            alert,
            MALWARE_CONTAINMENT_PLAYBOOK["trigger_conditions"]
        )

        assert triggered is False


class TestActionExecution:
    """Test individual action execution."""

    @pytest.mark.asyncio
    async def test_execute_isolate_host_action(self):
        """Test executing host isolation action."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "isolate_host",
            "params": {"host": "192.168.1.100", "method": "network"}
        }

        with patch('services.automation_orchestrator.main.call_firewall_api') as mock_fw:
            mock_fw.return_value = {"success": True, "rule_id": "FW-001"}

            result = await execute_action(action)

            assert result["success"] is True
            assert "rule_id" in result

    @pytest.mark.asyncio
    async def test_execute_quarantine_file_action(self):
        """Test executing file quarantine action."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "quarantine_file",
            "params": {"file_hash": "abc123", "endpoint_id": "EP-001"}
        }

        with patch('services.automation_orchestrator.main.call_edr_api') as mock_edr:
            mock_edr.return_value = {"success": True, "quarantine_id": "QT-001"}

            result = await execute_action(action)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_block_ip_action(self):
        """Test executing IP block action."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "block_ip",
            "params": {"ip": "1.2.3.4", "duration": 86400}
        }

        with patch('services.automation_orchestrator.main.call_firewall_api') as mock_fw:
            mock_fw.return_value = {"success": True}

            result = await execute_action(action)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_disable_user_action(self):
        """Test executing disable user action."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "disable_user",
            "params": {"username": "john.doe", "domain": "CORP"}
        }

        with patch('services.automation_orchestrator.main.call_ad_api') as mock_ad:
            mock_ad.return_value = {"success": True}

            result = await execute_action(action)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_kill_process_action(self):
        """Test executing kill process action."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "kill_process",
            "params": {"endpoint_id": "EP-001", "process_id": 12345}
        }

        with patch('services.automation_orchestrator.main.call_edr_api') as mock_edr:
            mock_edr.return_value = {"success": True}

            result = await execute_action(action)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_action_failure(self):
        """Test handling action execution failure."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "isolate_host",
            "params": {"host": "invalid"}
        }

        with patch('services.automation_orchestrator.main.call_firewall_api') as mock_fw:
            mock_fw.return_value = {"success": False, "error": "Host not found"}

            result = await execute_action(action)

            assert result["success"] is False
            assert "error" in result


class TestPlaybookExecution:
    """Test full playbook execution."""

    @pytest.mark.asyncio
    async def test_execute_malware_containment_playbook(self):
        """Test executing malware containment playbook."""
        from services.automation_orchestrator.main import execute_playbook

        alert = {
            "alert_id": "ALT-001",
            "alert_type": "malware",
            "risk_level": "critical",
            "source_ip": "192.168.1.100",
            "file_hash": "abc123"
        }

        with patch('services.automation_orchestrator.main.execute_action') as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await execute_playbook(MALWARE_CONTAINMENT_PLAYBOOK, alert)

            assert result["playbook_id"] == MALWARE_CONTAINMENT_PLAYBOOK["playbook_id"]
            assert result["status"] in ["completed", "partial"]
            assert result["actions_executed"] > 0

    @pytest.mark.asyncio
    async def test_execute_playbook_sequential(self):
        """Test executing playbook actions sequentially."""
        from services.automation_orchestrator.main import execute_playbook

        alert = {"alert_id": "ALT-001"}

        execution_order = []

        async def mock_execute(action):
            execution_order.append(action["action"])
            return {"success": True, "action": action["action"]}

        with patch('services.automation_orchestrator.main.execute_action', side_effect=mock_execute):
            result = await execute_playbook(MALWARE_CONTAINMENT_PLAYBOOK, alert)

            # Actions should execute in order
            assert len(execution_order) == len(MALWARE_CONTAINMENT_PLAYBOOK["actions"])

    @pytest.mark.asyncio
    async def test_execute_playbook_with_dependencies(self):
        """Test executing playbook with action dependencies."""
        from services.automation_orchestrator.main import execute_playbook

        playbook = {
            "playbook_id": "test-playbook",
            "actions": [
                {"action": "step1", "depends_on": None},
                {"action": "step2", "depends_on": "step1"},
                {"action": "step3", "depends_on": "step1"},
                {"action": "step4", "depends_on": ["step2", "step3"]}
            ]
        }

        alert = {"alert_id": "ALT-001"}

        execution_order = []

        async def mock_execute(action):
            execution_order.append(action["action"])
            return {"success": True}

        with patch('services.automation_orchestrator.main.execute_action', side_effect=mock_execute):
            result = await execute_playbook(playbook, alert)

            # step1 must be before step2/step3
            step1_idx = execution_order.index("step1")
            step2_idx = execution_order.index("step2")
            step3_idx = execution_order.index("step3")

            assert step1_idx < step2_idx
            assert step1_idx < step3_idx

    @pytest.mark.asyncio
    async def test_execute_playbook_stop_on_failure(self):
        """Test playbook stops on action failure."""
        from services.automation_orchestrator.main import execute_playbook

        alert = {"alert_id": "ALT-001"}

        call_count = 0

        async def mock_execute(action):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return {"success": False, "error": "Action failed"}
            return {"success": True}

        with patch('services.automation_orchestrator.main.execute_action', side_effect=mock_execute):
            result = await execute_playbook(MALWARE_CONTAINMENT_PLAYBOOK, alert, stop_on_failure=True)

            # Should stop after second action fails
            assert call_count == 2
            assert result["status"] == "failed"

    @pytest.mark.asyncio
    async def test_execute_playbook_continue_on_failure(self):
        """Test playbook continues on action failure."""
        from services.automation_orchestrator.main import execute_playbook

        alert = {"alert_id": "ALT-001"}

        async def mock_execute(action):
            if action["action"] == "isolate_host":
                return {"success": False, "error": "Failed"}
            return {"success": True}

        with patch('services.automation_orchestrator.main.execute_action', side_effect=mock_execute):
            result = await execute_playbook(MALWARE_CONTAINMENT_PLAYBOOK, alert, stop_on_failure=False)

            # Should complete all actions
            assert result["actions_executed"] == len(MALWARE_CONTAINMENT_PLAYBOOK["actions"])


class TestPlaybookRollback:
    """Test playbook rollback actions."""

    @pytest.mark.asyncio
    async def test_execute_rollback_actions(self):
        """Test executing rollback actions."""
        from services.automation_orchestrator.main import rollback_playbook

        execution_result = {
            "playbook_id": "test-playbook",
            "executed_actions": [
                {"action": "isolate_host", "result": {"success": True, "host": "192.168.1.100"}},
                {"action": "disable_user", "result": {"success": True, "user": "john.doe"}}
            ]
        }

        rollback_actions = [
            {"action": "unisolate_host", "params_mapping": {"host": "isolate_host.host"}},
            {"action": "enable_user", "params_mapping": {"user": "disable_user.user"}}
        ]

        with patch('services.automation_orchestrator.main.execute_action') as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await rollback_playbook(execution_result, rollback_actions)

            assert result["actions_rolled_back"] == 2

    @pytest.mark.asyncio
    async def test_rollback_on_playbook_failure(self):
        """Test automatic rollback on playbook failure."""
        from services.automation_orchestrator.main import execute_playbook_with_rollback

        alert = {"alert_id": "ALT-001"}

        async def mock_execute(action):
            if "rollback" not in action["action"]:
                return {"success": True}
            return {"success": True}

        with patch('services.automation_orchestrator.main.execute_action', side_effect=mock_execute):
            # Force failure in middle of playbook
            with patch('services.automation_orchestrator.main.execute_playbook') as mock_playbook:
                mock_playbook.return_value = {
                    "status": "failed",
                    "executed_actions": [
                        {"action": "step1", "result": {"success": True}}
                    ]
                }

                result = await execute_playbook_with_rollback(
                    MALWARE_CONTAINMENT_PLAYBOOK,
                    alert,
                    auto_rollback=True
                )

                assert result["rollback_executed"] is True


class TestPlaybookApproval:
    """Test playbook approval workflow."""

    @pytest.mark.asyncio
    async def test_require_approval_for_destructive_actions(self):
        """Test destructive actions require approval."""
        from services.automation_orchestrator.main import requires_approval

        destructive_actions = [
            "isolate_host",
            "shutdown_server",
            "delete_database",
            "block_ip_range"
        ]

        for action in destructive_actions:
            assert requires_approval(action) is True

    @pytest.mark.asyncio
    async def test_non_destructive_no_approval(self):
        """Test non-destructive actions don't require approval."""
        from services.automation_orchestrator.main import requires_approval

        safe_actions = [
            "send_notification",
            "create_ticket",
            "log_event"
        ]

        for action in safe_actions:
            assert requires_approval(action) is False

    @pytest.mark.asyncio
    async def test_request_approval(self):
        """Test requesting playbook approval."""
        from services.automation_orchestrator.main import request_approval

        playbook = MALWARE_CONTAINMENT_PLAYBOOK
        alert = {"alert_id": "ALT-001", "risk_level": "critical"}

        with patch('services.automation_orchestrator.main.notify_approvers') as mock_notify:
            approval_id = await request_approval(playbook, alert)

            assert approval_id is not None
            assert "approval" in approval_id.lower()

    @pytest.mark.asyncio
    async def test_check_approval_status(self):
        """Test checking approval status."""
        from services.automation_orchestrator.main import check_approval_status

        approval_id = "APR-001"

        with patch('services.automation_orchestrator.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = {
                "approval_id": approval_id,
                "status": "approved",
                "approved_by": "jane.smith"
            }

            status = await check_approval_status(approval_id)

            assert status["status"] == "approved"


class TestPlaybookTimeout:
    """Test playbook timeout handling."""

    @pytest.mark.asyncio
    async def test_playbook_timeout(self):
        """Test playbook execution timeout."""
        from services.automation_orchestrator.main import execute_playbook

        alert = {"alert_id": "ALT-001"}

        async def mock_execute(action):
            import asyncio
            await asyncio.sleep(2)  # Exceed timeout
            return {"success": True}

        with patch('services.automation_orchestrator.main.execute_action', side_effect=mock_execute):
            result = await execute_playbook(
                MALWARE_CONTAINMENT_PLAYBOOK,
                alert,
                timeout_seconds=1
            )

            assert result["status"] == "timed_out"

    @pytest.mark.asyncio
    async def test_action_timeout(self):
        """Test individual action timeout."""
        from services.automation_orchestrator.main import execute_action

        action = {
            "action": "long_running",
            "timeout_seconds": 1
        }

        async def mock_impl(params):
            import asyncio
            await asyncio.sleep(2)

        with patch('services.automation_orchestrator.main.implement_action', side_effect=mock_impl):
            result = await execute_action(action)

            assert result["success"] is False
            assert "timeout" in result.get("error", "").lower()


class TestPlaybookMetrics:
    """Test playbook execution metrics."""

    @pytest.mark.asyncio
    async def test_record_playbook_execution(self):
        """Test recording playbook execution metrics."""
        from services.automation_orchestrator.main import record_playbook_execution

        execution = {
            "playbook_id": "MALWARE_CONTAINMENT_PLAYBOOK",
            "alert_id": "ALT-001",
            "status": "completed",
            "duration_seconds": 15.5,
            "actions_executed": 5,
            "actions_succeeded": 5
        }

        with patch('services.automation_orchestrator.main.metrics_logger') as mock_logger:
            await record_playbook_execution(execution)

            mock_logger.info.assert_called_once()

    def test_calculate_playbook_success_rate(self):
        """Test calculating playbook success rate."""
        from services.automation_orchestrator.main import calculate_success_rate

        executions = [
            {"status": "completed"},
            {"status": "completed"},
            {"status": "failed"},
            {"status": "completed"}
        ]

        rate = calculate_success_rate(executions)

        assert rate == 0.75  # 3/4


class TestIntegrationAPIs:
    """Test integration with external APIs."""

    @pytest.mark.asyncio
    async def test_firewall_api_integration(self):
        """Test firewall API integration."""
        from services.automation_orchestrator.main import call_firewall_api

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"rule_id": "FW-001", "success": True}
            mock_post.return_value = mock_response

            result = await call_firewall_api({
                "action": "block_ip",
                "ip": "1.2.3.4"
            })

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_edr_api_integration(self):
        """Test EDR API integration."""
        from services.automation_orchestrator.main import call_edr_api

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"quarantine_id": "QT-001", "success": True}
            mock_post.return_value = mock_response

            result = await call_edr_api({
                "action": "quarantine_file",
                "hash": "abc123"
            })

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_ad_api_integration(self):
        """Test Active Directory API integration."""
        from services.automation_orchestrator.main import call_ad_api

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"success": True}
            mock_post.return_value = mock_response

            result = await call_ad_api({
                "action": "disable_user",
                "username": "john.doe"
            })

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_siem_api_integration(self):
        """Test SIEM API integration."""
        from services.automation_orchestrator.main import call_siem_api

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"event_id": "EV-001", "success": True}
            mock_post.return_value = mock_response

            result = await call_siem_api({
                "action": "create_event",
                "event_data": {"description": "Host isolated"}
            })

            assert result["success"] is True


class TestPlaybookMatching:
    """Test playbook matching and selection."""

    @pytest.mark.asyncio
    async def test_find_matching_playbook(self):
        """Test finding matching playbook for alert."""
        from services.automation_orchestrator.main import find_matching_playbook

        alert = {
            "alert_type": "malware",
            "risk_level": "critical"
        }

        playbook = await find_matching_playbook(alert)

        assert playbook is not None
        assert playbook["playbook_id"] == "MALWARE_CONTAINMENT_PLAYBOOK"

    @pytest.mark.asyncio
    async def test_no_matching_playbook(self):
        """Test when no playbook matches."""
        from services.automation_orchestrator.main import find_matching_playbook

        alert = {
            "alert_type": "unknown_type",
            "risk_level": "low"
        }

        playbook = await find_matching_playbook(alert)

        assert playbook is None

    @pytest.mark.asyncio
    async def test_multiple_matching_playbooks_priority(self):
        """Test selecting highest priority playbook when multiple match."""
        from services.automation_orchestrator.main import find_matching_playbook

        alert = {
            "alert_type": "malware",
            "title": "Ransomware encryption detected",
            "risk_level": "critical"
        }

        playbook = await find_matching_playbook(alert)

        # Ransomware playbook should have higher priority
        assert playbook["playbook_id"] == "RANSOMWARE_RESPONSE_PLAYBOOK"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
