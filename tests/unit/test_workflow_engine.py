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
Unit tests for Workflow Engine Service.
Tests Temporal workflow orchestration, step execution, and state management.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from enum import Enum


class WorkflowStatus(str, Enum):
    """Workflow status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class StepStatus(str, Enum):
    """Step status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TestWorkflowCreation:
    """Test workflow creation and initialization."""

    def test_create_workflow(self):
        """Test creating a new workflow."""
        from services.workflow_engine.main import create_workflow
        from services.shared.models import WorkflowDefinition

        definition = WorkflowDefinition(
            workflow_id="WF-001",
            name="Malware Response",
            description="Automated malware containment",
            steps=[
                {"step_id": "step1", "action": "isolate_host", "params": {"host": "192.168.1.1"}},
                {"step_id": "step2", "action": "quarantine_file", "params": {"hash": "abc123"}},
            ]
        )

        workflow = create_workflow(definition)

        assert workflow["workflow_id"] == "WF-001"
        assert workflow["status"] == WorkflowStatus.PENDING
        assert workflow["progress"] == 0
        assert len(workflow["steps"]) == 2

    def test_create_workflow_with_timeout(self):
        """Test creating workflow with timeout."""
        from services.workflow_engine.main import create_workflow

        workflow = create_workflow(
            workflow_id="WF-002",
            name="Timeout Test",
            timeout_seconds=300
        )

        assert workflow["timeout_seconds"] == 300
        assert "expires_at" in workflow

    def test_create_workflow_with_triggers(self):
        """Test creating workflow with alert triggers."""
        from services.workflow_engine.main import create_workflow

        triggers = {
            "alert_type": "malware",
            "risk_level": "critical",
            "confidence_threshold": 90
        }

        workflow = create_workflow(
            workflow_id="WF-003",
            name="Triggered Workflow",
            triggers=triggers
        )

        assert workflow["triggers"] == triggers


class TestWorkflowExecution:
    """Test workflow execution logic."""

    @pytest.mark.asyncio
    async def test_start_workflow(self):
        """Test starting a workflow."""
        from services.workflow_engine.main import start_workflow

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.PENDING,
            "steps": [
                {"step_id": "step1", "action": "test", "status": StepStatus.PENDING}
            ]
        }

        with patch('services.workflow_engine.main.execute_step') as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await start_workflow(workflow)

            assert result["status"] == WorkflowStatus.RUNNING
            mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_step_success(self):
        """Test successful step execution."""
        from services.workflow_engine.main import execute_step

        step = {
            "step_id": "step1",
            "action": "isolate_host",
            "params": {"host": "192.168.1.1"},
            "status": StepStatus.PENDING
        }

        with patch('services.workflow_engine.main.call_automation_orchestrator') as mock_auto:
            mock_auto.return_value = {
                "success": True,
                "output": "Host isolated successfully"
            }

            result = await execute_step(step)

            assert result["status"] == StepStatus.COMPLETED
            assert result["output"] == "Host isolated successfully"

    @pytest.mark.asyncio
    async def test_execute_step_failure(self):
        """Test failed step execution."""
        from services.workflow_engine.main import execute_step

        step = {
            "step_id": "step1",
            "action": "isolate_host",
            "params": {"host": "invalid"},
            "status": StepStatus.PENDING
        }

        with patch('services.workflow_engine.main.call_automation_orchestrator') as mock_auto:
            mock_auto.return_value = {
                "success": False,
                "error": "Host not found"
            }

            result = await execute_step(step)

            assert result["status"] == StepStatus.FAILED
            assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_workflow_sequential_steps(self):
        """Test executing workflow with sequential steps."""
        from services.workflow_engine.main import execute_workflow

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.PENDING,
            "execution_mode": "sequential",
            "steps": [
                {"step_id": "step1", "action": "test1", "status": StepStatus.PENDING},
                {"step_id": "step2", "action": "test2", "status": StepStatus.PENDING},
                {"step_id": "step3", "action": "test3", "status": StepStatus.PENDING},
            ]
        }

        execution_order = []

        async def mock_execute(step):
            execution_order.append(step["step_id"])
            return {"step_id": step["step_id"], "status": StepStatus.COMPLETED}

        with patch('services.workflow_engine.main.execute_step', side_effect=mock_execute):
            result = await execute_workflow(workflow)

            assert execution_order == ["step1", "step2", "step3"]
            assert result["status"] == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_workflow_parallel_steps(self):
        """Test executing workflow with parallel steps."""
        from services.workflow_engine.main import execute_workflow
        import asyncio

        workflow = {
            "workflow_id": "WF-002",
            "status": WorkflowStatus.PENDING,
            "execution_mode": "parallel",
            "steps": [
                {"step_id": "step1", "action": "test1", "status": StepStatus.PENDING},
                {"step_id": "step2", "action": "test2", "status": StepStatus.PENDING},
                {"step_id": "step3", "action": "test3", "status": StepStatus.PENDING},
            ]
        }

        async def mock_execute(step):
            await asyncio.sleep(0.1)  # Simulate work
            return {"step_id": step["step_id"], "status": StepStatus.COMPLETED}

        with patch('services.workflow_engine.main.execute_step', side_effect=mock_execute):
            result = await execute_workflow(workflow)

            assert result["status"] == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_workflow_with_conditional_steps(self):
        """Test workflow with conditional step execution."""
        from services.workflow_engine.main import execute_workflow

        workflow = {
            "workflow_id": "WF-003",
            "status": WorkflowStatus.PENDING,
            "steps": [
                {
                    "step_id": "step1",
                    "action": "check_condition",
                    "status": StepStatus.PENDING,
                    "condition": {"risk_level": "critical"}
                },
                {
                    "step_id": "step2",
                    "action": "critical_action",
                    "status": StepStatus.PENDING,
                    "depends_on": "step1",
                    "condition_result": True
                }
            ]
        }

        with patch('services.workflow_engine.main.execute_step') as mock_execute:
            mock_execute.return_value = {"status": StepStatus.COMPLETED}

            result = await execute_workflow(workflow)

            assert result["status"] == WorkflowStatus.COMPLETED


class TestWorkflowStateManagement:
    """Test workflow state persistence and recovery."""

    @pytest.mark.asyncio
    async def test_save_workflow_state(self):
        """Test saving workflow state."""
        from services.workflow_engine.main import save_workflow_state

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.RUNNING,
            "progress": 50,
            "steps": []
        }

        with patch('services.workflow_engine.main.db_manager') as mock_db:
            await save_workflow_state(workflow)

            mock_db.upsert.assert_called_once()

    @pytest.mark.asyncio
    async def test_load_workflow_state(self):
        """Test loading workflow state."""
        from services.workflow_engine.main import load_workflow_state

        saved_workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.RUNNING,
            "progress": 50
        }

        with patch('services.workflow_engine.main.db_manager') as mock_db:
            mock_db.fetch_one.return_value = saved_workflow

            loaded = await load_workflow_state("WF-001")

            assert loaded["workflow_id"] == "WF-001"
            assert loaded["progress"] == 50

    @pytest.mark.asyncio
    async def test_workflow_checkpoint(self):
        """Test creating workflow checkpoint."""
        from services.workflow_engine.main import create_checkpoint

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.RUNNING,
            "current_step": "step2",
            "steps": [
                {"step_id": "step1", "status": StepStatus.COMPLETED},
                {"step_id": "step2", "status": StepStatus.RUNNING},
            ]
        }

        checkpoint = await create_checkpoint(workflow)

        assert "checkpoint_id" in checkpoint
        assert checkpoint["workflow_id"] == "WF-001"
        assert "timestamp" in checkpoint

    @pytest.mark.asyncio
    async def test_workflow_resume_from_checkpoint(self):
        """Test resuming workflow from checkpoint."""
        from services.workflow_engine.main import resume_from_checkpoint

        checkpoint = {
            "checkpoint_id": "CP-001",
            "workflow_id": "WF-001",
            "state": {
                "status": WorkflowStatus.RUNNING,
                "current_step": "step2"
            }
        }

        with patch('services.workflow_engine.main.execute_workflow') as mock_execute:
            mock_execute.return_value = {"status": WorkflowStatus.COMPLETED}

            result = await resume_from_checkpoint(checkpoint)

            assert result["status"] == WorkflowStatus.COMPLETED


class TestWorkflowTimeout:
    """Test workflow timeout handling."""

    @pytest.mark.asyncio
    async def test_workflow_timeout_during_execution(self):
        """Test workflow times out during execution."""
        from services.workflow_engine.main import execute_workflow

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.PENDING,
            "timeout_seconds": 1,
            "steps": [
                {"step_id": "step1", "action": "long_running", "status": StepStatus.PENDING}
            ]
        }

        async def mock_execute(step):
            import asyncio
            await asyncio.sleep(2)  # Exceed timeout
            return {"status": StepStatus.COMPLETED}

        with patch('services.workflow_engine.main.execute_step', side_effect=mock_execute):
            result = await execute_workflow(workflow)

            assert result["status"] == WorkflowStatus.TIMED_OUT

    def test_check_workflow_timeout(self):
        """Test checking if workflow has timed out."""
        from services.workflow_engine.main import check_workflow_timeout

        # Expired workflow
        workflow = {
            "workflow_id": "WF-001",
            "expires_at": datetime.now() - timedelta(seconds=1)
        }

        assert check_workflow_timeout(workflow) is True

        # Not expired
        workflow["expires_at"] = datetime.now() + timedelta(seconds=60)

        assert check_workflow_timeout(workflow) is False


class TestWorkflowRetry:
    """Test workflow retry logic."""

    @pytest.mark.asyncio
    async def test_step_retry_on_failure(self):
        """Test retrying failed steps."""
        from services.workflow_engine.main import execute_step_with_retry

        step = {
            "step_id": "step1",
            "action": "flakey_action",
            "max_retries": 3
        }

        attempt_count = 0

        async def mock_execute(step):
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                return {"success": False, "error": "Temporary error"}
            return {"success": True}

        with patch('services.workflow_engine.main.execute_step', side_effect=mock_execute):
            result = await execute_step_with_retry(step)

            assert result["success"] is True
            assert attempt_count == 3

    @pytest.mark.asyncio
    async def test_step_retry_exhausted(self):
        """Test step retry exhausted."""
        from services.workflow_engine.main import execute_step_with_retry

        step = {
            "step_id": "step1",
            "action": "failing_action",
            "max_retries": 3
        }

        async def mock_execute(step):
            return {"success": False, "error": "Permanent error"}

        with patch('services.workflow_engine.main.execute_step', side_effect=mock_execute):
            result = await execute_step_with_retry(step)

            assert result["success"] is False
            assert "retry_exhausted" in result or "error" in result


class TestWorkflowCancellation:
    """Test workflow cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_running_workflow(self):
        """Test cancelling a running workflow."""
        from services.workflow_engine.main import cancel_workflow

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.RUNNING,
            "steps": [
                {"step_id": "step1", "status": StepStatus.COMPLETED},
                {"step_id": "step2", "status": StepStatus.RUNNING},
            ]
        }

        result = await cancel_workflow(workflow)

        assert result["status"] == WorkflowStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_workflow_rollback(self):
        """Test rollback on workflow cancellation."""
        from services.workflow_engine.main import cancel_workflow_with_rollback

        workflow = {
            "workflow_id": "WF-001",
            "status": WorkflowStatus.RUNNING,
            "steps": [
                {
                    "step_id": "step1",
                    "status": StepStatus.COMPLETED,
                    "rollback_action": "undo_step1"
                },
                {
                    "step_id": "step2",
                    "status": StepStatus.RUNNING
                }
            ]
        }

        with patch('services.workflow_engine.main.execute_rollback') as mock_rollback:
            await cancel_workflow_with_rollback(workflow)

            mock_rollback.assert_called_once()


class TestWorkflowProgress:
    """Test workflow progress tracking."""

    def test_calculate_progress(self):
        """Test calculating workflow progress."""
        from services.workflow_engine.main import calculate_progress

        workflow = {
            "steps": [
                {"step_id": "step1", "status": StepStatus.COMPLETED},
                {"step_id": "step2", "status": StepStatus.COMPLETED},
                {"step_id": "step3", "status": StepStatus.RUNNING},
                {"step_id": "step4", "status": StepStatus.PENDING},
            ]
        }

        progress = calculate_progress(workflow)

        # 2 completed + 0.5 running = 2.5 / 4 = 62.5%
        assert progress == 62.5

    def test_update_progress(self):
        """Test updating workflow progress."""
        from services.workflow_engine.main import update_progress

        workflow = {
            "workflow_id": "WF-001",
            "progress": 0,
            "steps": []
        }

        update_progress(workflow, 50)

        assert workflow["progress"] == 50


class TestWorkflowEvents:
    """Test workflow event emission and handling."""

    @pytest.mark.asyncio
    async def test_emit_workflow_event(self):
        """Test emitting workflow events."""
        from services.workflow_engine.main import emit_event

        event = {
            "workflow_id": "WF-001",
            "event_type": "step_completed",
            "step_id": "step1",
            "timestamp": datetime.now().isoformat()
        }

        with patch('services.workflow_engine.main.event_publisher') as mock_publisher:
            await emit_event(event)

            mock_publisher.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_workflow_event_handlers(self):
        """Test workflow event handlers."""
        from services.workflow_engine.main import register_event_handler, handle_event

        handler_called = []

        async def test_handler(event):
            handler_called.append(event["event_type"])

        register_event_handler("step_completed", test_handler)

        event = {
            "workflow_id": "WF-001",
            "event_type": "step_completed"
        }

        await handle_event(event)

        assert "step_completed" in handler_called


class TestWorkflowValidation:
    """Test workflow definition validation."""

    def test_validate_workflow_definition(self):
        """Test validating workflow definition."""
        from services.workflow_engine.main import validate_workflow_definition

        valid_workflow = {
            "workflow_id": "WF-001",
            "name": "Test Workflow",
            "steps": [
                {"step_id": "step1", "action": "test"}
            ]
        }

        assert validate_workflow_definition(valid_workflow) is True

    def test_validate_workflow_missing_steps(self):
        """Test validation fails with missing steps."""
        from services.workflow_engine.main import validate_workflow_definition

        invalid_workflow = {
            "workflow_id": "WF-001",
            "name": "Test Workflow",
            "steps": []
        }

        assert validate_workflow_definition(invalid_workflow) is False

    def test_validate_workflow_circular_dependencies(self):
        """Test detecting circular dependencies."""
        from services.workflow_engine.main import validate_workflow_definition

        workflow_with_circular = {
            "workflow_id": "WF-001",
            "steps": [
                {
                    "step_id": "step1",
                    "action": "test1",
                    "depends_on": "step3"
                },
                {
                    "step_id": "step2",
                    "action": "test2",
                    "depends_on": "step1"
                },
                {
                    "step_id": "step3",
                    "action": "test3",
                    "depends_on": "step2"
                }
            ]
        }

        assert validate_workflow_definition(workflow_with_circular) is False


class TestWorkflowMetrics:
    """Test workflow metrics and monitoring."""

    @pytest.mark.asyncio
    async def test_record_workflow_metric(self):
        """Test recording workflow metrics."""
        from services.workflow_engine.main import record_workflow_metric

        metric = {
            "workflow_id": "WF-001",
            "metric_type": "execution_time",
            "value": 5.2,
            "unit": "seconds"
        }

        with patch('services.workflow_engine.main.metrics_logger') as mock_logger:
            await record_workflow_metric(metric)

            mock_logger.info.assert_called_once()

    def test_calculate_workflow_duration(self):
        """Test calculating workflow duration."""
        from services.workflow_engine.main import calculate_workflow_duration

        workflow = {
            "started_at": datetime.now() - timedelta(seconds=10),
            "completed_at": datetime.now()
        }

        duration = calculate_workflow_duration(workflow)

        assert duration == 10.0

    def test_get_workflow_statistics(self):
        """Test getting workflow statistics."""
        from services.workflow_engine.main import get_workflow_statistics

        workflows = [
            {"status": WorkflowStatus.COMPLETED},
            {"status": WorkflowStatus.COMPLETED},
            {"status": WorkflowStatus.FAILED},
            {"status": WorkflowStatus.RUNNING}
        ]

        stats = get_workflow_statistics(workflows)

        assert stats["total"] == 4
        assert stats["completed"] == 2
        assert stats["failed"] == 1
        assert stats["running"] == 1


class TestWorkflowIntegration:
    """Test workflow integration with other services."""

    @pytest.mark.asyncio
    async def test_trigger_workflow_from_alert(self):
        """Test triggering workflow from alert."""
        from services.workflow_engine.main import trigger_workflow_from_alert
        from services.shared.models import SecurityAlert

        alert = SecurityAlert(
            alert_id="ALT-001",
            alert_type="malware",
            severity="critical",
            title="Malware Detected",
            description="Test"
        )

        with patch('services.workflow_engine.main.find_matching_workflow') as mock_find, \
             patch('services.workflow_engine.main.execute_workflow') as mock_execute:

            mock_find.return_value = {
                "workflow_id": "WF-001",
                "triggers": {"alert_type": "malware", "risk_level": "critical"}
            }

            mock_execute.return_value = {"status": WorkflowStatus.COMPLETED}

            result = await trigger_workflow_from_alert(alert)

            assert result["status"] == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_workflow_automation_integration(self):
        """Test workflow calling automation orchestrator."""
        from services.workflow_engine.main import call_automation_orchestrator

        action = {
            "playbook": "MALWARE_CONTAINMENT",
            "params": {"host": "192.168.1.1"}
        }

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"success": True}
            mock_post.return_value = mock_response

            result = await call_automation_orchestrator(action)

            assert result["success"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
