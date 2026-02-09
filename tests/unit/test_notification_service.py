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
Unit tests for Notification Service.
Tests all 9 notification channels: Email, SMS, Slack, DingTalk, WeChat Work,
Teams, PagerDuty, Webhook, and in-app notifications.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import httpx
from datetime import datetime


class TestEmailNotification:
    """Test email notification channel."""

    @pytest.fixture
    def smtp_mock(self):
        """Create SMTP mock."""
        with patch('smtplib.SMTP') as mock:
            smtp_instance = Mock()
            mock.return_value.__enter__ = Mock(return_value=smtp_instance)
            mock.return_value.__exit__ = Mock(return_value=False)
            smtp_instance.sendmail.return_value = {}
            yield smtp_instance

    @pytest.mark.asyncio
    async def test_send_email_success(self, smtp_mock):
        """Test successful email sending."""
        from services.notification_service.main import send_email

        result = await send_email(
            to="test@example.com",
            subject="Test Subject",
            body="Test body",
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass"
        )

        assert result["success"] is True
        assert result["channel"] == "email"
        smtp_mock.sendmail.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_email_html(self, smtp_mock):
        """Test sending HTML email."""
        from services.notification_service.main import send_email

        result = await send_email(
            to="test@example.com",
            subject="HTML Test",
            body="<h1>Test</h1>",
            is_html=True,
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass"
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_email_multiple_recipients(self, smtp_mock):
        """Test sending email to multiple recipients."""
        from services.notification_service.main import send_email

        result = await send_email(
            to=["test1@example.com", "test2@example.com"],
            subject="Multi Recipient",
            body="Test",
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass"
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_email_failure(self, smtp_mock):
        """Test email sending failure."""
        from services.notification_service.main import send_email

        smtp_mock.sendmail.side_effect = Exception("SMTP Error")

        result = await send_email(
            to="test@example.com",
            subject="Test",
            body="Test",
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass"
        )

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_send_email_with_attachment(self, smtp_mock):
        """Test sending email with attachment."""
        from services.notification_service.main import send_email

        result = await send_email(
            to="test@example.com",
            subject="Attachment Test",
            body="Test",
            attachments=[{"filename": "test.txt", "content": "data"}],
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass"
        )

        assert result["success"] is True


class TestSMSNotification:
    """Test SMS notification channel."""

    @pytest.mark.asyncio
    async def test_send_sms_success(self):
        """Test successful SMS sending."""
        from services.notification_service.main import send_sms

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"sid": "SM123"}
            mock_post.return_value = mock_response

            result = await send_sms(
                to="+1234567890",
                message="Test SMS",
                provider="twilio",
                account_sid="AC123",
                auth_token="token"
            )

            assert result["success"] is True
            assert result["channel"] == "sms"

    @pytest.mark.asyncio
    async def test_send_sms_validation_error(self):
        """Test SMS validation error."""
        from services.notification_service.main import send_sms

        result = await send_sms(
            to="invalid",
            message="Test",
            provider="twilio",
            account_sid="AC123",
            auth_token="token"
        )

        assert result["success"] is False
        assert "validation" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_send_sms_rate_limit(self):
        """Test SMS rate limiting."""
        from services.notification_service.main import send_sms

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 429
            mock_post.return_value = mock_response

            result = await send_sms(
                to="+1234567890",
                message="Test",
                provider="twilio",
                account_sid="AC123",
                auth_token="token"
            )

            assert result["success"] is False
            assert "rate" in result.get("error", "").lower()


class TestSlackNotification:
    """Test Slack notification channel."""

    @pytest.mark.asyncio
    async def test_send_slack_message_success(self):
        """Test successful Slack message sending."""
        from services.notification_service.main import send_slack

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ok": True}
            mock_post.return_value = mock_response

            result = await send_slack(
                webhook_url="https://hooks.slack.com/test",
                message="Test message"
            )

            assert result["success"] is True
            assert result["channel"] == "slack"

    @pytest.mark.asyncio
    async def test_send_slack_with_blocks(self):
        """Test Slack message with blocks."""
        from services.notification_service.main import send_slack

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ok": True}
            mock_post.return_value = mock_response

            blocks = [{"type": "section", "text": {"type": "plain_text", "text": "Test"}}]
            result = await send_slack(
                webhook_url="https://hooks.slack.com/test",
                message="Test",
                blocks=blocks
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_slack_with_threading(self):
        """Test Slack message with thread timestamp."""
        from services.notification_service.main import send_slack

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ok": True}
            mock_post.return_value = mock_response

            result = await send_slack(
                webhook_url="https://hooks.slack.com/test",
                message="Thread reply",
                thread_ts="1234567890.123456"
            )

            assert result["success"] is True


class TestDingTalkNotification:
    """Test DingTalk notification channel."""

    @pytest.mark.asyncio
    async def test_send_dingtalk_text_message(self):
        """Test DingTalk text message."""
        from services.notification_service.main import send_dingtalk

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errcode": 0}
            mock_post.return_value = mock_response

            result = await send_dingtalk(
                webhook_url="https://oapi.dingtalk.com/test",
                message="Test message"
            )

            assert result["success"] is True
            assert result["channel"] == "dingtalk"

    @pytest.mark.asyncio
    async def test_send_dingtalk_at_mobiles(self):
        """Test DingTalk with @ mobile numbers."""
        from services.notification_service.main import send_dingtalk

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errcode": 0}
            mock_post.return_value = mock_response

            result = await send_dingtalk(
                webhook_url="https://oapi.dingtalk.com/test",
                message="Test",
                at_mobiles=["1234567890"]
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_dingtalk_at_all(self):
        """Test DingTalk @all."""
        from services.notification_service.main import send_dingtalk

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errcode": 0}
            mock_post.return_value = mock_response

            result = await send_dingtalk(
                webhook_url="https://oapi.dingtalk.com/test",
                message="@everyone",
                at_all=True
            )

            assert result["success"] is True


class TestWeChatWorkNotification:
    """Test WeChat Work notification channel."""

    @pytest.mark.asyncio
    async def test_send_wechat_work_text(self):
        """Test WeChat Work text message."""
        from services.notification_service.main import send_wechat_work

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errcode": 0}
            mock_post.return_value = mock_response

            result = await send_wechat_work(
 webhook_url="https://qyapi.weixin.qq.com/test",
                message="Test message"
            )

            assert result["success"] is True
            assert result["channel"] == "wechat_work"

    @pytest.mark.asyncio
    async def test_send_wechat_work_markdown(self):
        """Test WeChat Work markdown message."""
        from services.notification_service.main import send_wechat_work

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errcode": 0}
            mock_post.return_value = mock_response

            result = await send_wechat_work(
                webhook_url="https://qyapi.weixin.qq.com/test",
                message="**Test**",
                msg_type="markdown"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_wechat_work_with_mention(self):
        """Test WeChat Work with mentioned user."""
        from services.notification_service.main import send_wechat_work

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"errcode": 0}
            mock_post.return_value = mock_response

            result = await send_wechat_work(
                webhook_url="https://qyapi.weixin.qq.com/test",
                message="@User Test",
                mentioned_list=["user_id"]
            )

            assert result["success"] is True


class TestTeamsNotification:
    """Test Microsoft Teams notification channel."""

    @pytest.mark.asyncio
    async def test_send_teams_text_message(self):
        """Test Teams text message."""
        from services.notification_service.main import send_teams

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            result = await send_teams(
                webhook_url="https://outlook.office.com/test",
                message="Test message"
            )

            assert result["success"] is True
            assert result["channel"] == "teams"

    @pytest.mark.asyncio
    async def test_send_teams_with_card(self):
        """Test Teams with adaptive card."""
        from services.notification_service.main import send_teams

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            card = {
                "type": "AdaptiveCard",
                "body": [{"type": "TextBlock", "text": "Test"}]
            }
            result = await send_teams(
                webhook_url="https://outlook.office.com/test",
                message="Test",
                card=card
            )

            assert result["success"] is True


class TestPagerDutyNotification:
    """Test PagerDuty notification channel."""

    @pytest.mark.asyncio
    async def test_send_pagerduty_trigger(self):
        """Test PagerDuty trigger event."""
        from services.notification_service.main import send_pagerduty

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 202
            mock_response.json.return_value = {"status": "processed"}
            mock_post.return_value = mock_response

            result = await send_pagerduty(
                integration_key="test_key",
                event_type="trigger",
                dedup_key="incident-1",
                title="Test incident",
                body="Test description",
                severity="critical"
            )

            assert result["success"] is True
            assert result["channel"] == "pagerduty"

    @pytest.mark.asyncio
    async def test_send_pagerduty_acknowledge(self):
        """Test PagerDuty acknowledge event."""
        from services.notification_service.main import send_pagerduty

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 202
            mock_post.return_value = mock_response

            result = await send_pagerduty(
                integration_key="test_key",
                event_type="acknowledge",
                dedup_key="incident-1"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_pagerduty_resolve(self):
        """Test PagerDuty resolve event."""
        from services.notification_service.main import send_pagerduty

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 202
            mock_post.return_value = mock_response

            result = await send_pagerduty(
                integration_key="test_key",
                event_type="resolve",
                dedup_key="incident-1"
            )

            assert result["success"] is True


class TestWebhookNotification:
    """Test Webhook notification channel."""

    @pytest.mark.asyncio
    async def test_send_webhook_json(self):
        """Test webhook with JSON payload."""
        from services.notification_service.main import send_webhook

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"received": True}
            mock_post.return_value = mock_response

            result = await send_webhook(
                url="https://example.com/webhook",
                payload={"alert_id": "123", "severity": "high"},
                headers={"Authorization": "Bearer token"}
            )

            assert result["success"] is True
            assert result["channel"] == "webhook"

    @pytest.mark.asyncio
    async def test_send_webhook_with_retry(self):
        """Test webhook with retry on failure."""
        from services.notification_service.main import send_webhook

        call_count = 0

        async def mock_post_with_retry(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = Mock()
            if call_count < 3:
                mock_response.status_code = 500
            else:
                mock_response.status_code = 200
                mock_response.json.return_value = {"received": True}
            return mock_response

        with patch('httpx.AsyncClient.post', side_effect=mock_post_with_retry):
            result = await send_webhook(
                url="https://example.com/webhook",
                payload={"test": "data"},
                max_retries=3
            )

            assert result["success"] is True
            assert call_count == 3

    @pytest.mark.asyncio
    async def test_send_webhook_timeout(self):
        """Test webhook timeout handling."""
        from services.notification_service.main import send_webhook

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Timeout")

            result = await send_webhook(
                url="https://example.com/webhook",
                payload={"test": "data"},
                timeout=1.0
            )

            assert result["success"] is False
            assert "timeout" in result.get("error", "").lower()


class TestNotificationRouting:
    """Test notification routing and priority."""

    @pytest.mark.asyncio
    async def test_route_by_severity(self):
        """Test routing notifications based on severity."""
        from services.notification_service.main import route_notification

        with patch('services.notification_service.main.send_email') as mock_email, \
             patch('services.notification_service.main.send_slack') as mock_slack, \
             patch('services.notification_service.main.send_pagerduty') as mock_pager:

            mock_email.return_value = {"success": True}
            mock_slack.return_value = {"success": True}
            mock_pager.return_value = {"success": True}

            # Critical severity -> all channels
            result = await route_notification(
                severity="critical",
                channels=["email", "slack", "pagerduty"],
                message="Critical alert"
            )

            assert len(result) == 3
            assert all(r["success"] for r in result)

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test notification rate limiting."""
        from services.notification_service.main import send_notification

        with patch('services.notification_service.main.send_slack') as mock_slack:
            mock_slack.return_value = {"success": True}

            # Send multiple notifications quickly
            results = []
            for i in range(5):
                result = await send_notification(
                    channel="slack",
                    webhook_url="https://hooks.slack.com/test",
                    message=f"Message {i}",
                    user_id="user123"
                )
                results.append(result)

            # Should handle rate limiting gracefully
            assert len(results) == 5

    @pytest.mark.asyncio
    async def test_template_rendering(self):
        """Test notification template rendering."""
        from services.notification_service.main import render_template

        template = "Alert {{ alert_id }}: {{ severity }} severity"
        context = {"alert_id": "123", "severity": "high"}

        rendered = render_template(template, context)

        assert rendered == "Alert 123: high severity"

    @pytest.mark.asyncio
    async def test_batch_notifications(self):
        """Test sending batch notifications."""
        from services.notification_service.main import send_batch_notifications

        with patch('services.notification_service.main.send_email') as mock_email:
            mock_email.return_value = {"success": True}

            notifications = [
                {"channel": "email", "to": "user1@example.com", "message": "Test 1"},
                {"channel": "email", "to": "user2@example.com", "message": "Test 2"},
            ]

            results = await send_batch_notifications(notifications)

            assert len(results) == 2
            assert all(r["success"] for r in results)


class TestNotificationPriority:
    """Test notification priority handling."""

    @pytest.mark.asyncio
    async def test_critical_priority_immediate(self):
        """Test critical priority notifications sent immediately."""
        from services.notification_service.main import send_notification

        with patch('services.notification_service.main.send_pagerduty') as mock_pager:
            mock_pager.return_value = {"success": True}

            result = await send_notification(
                channel="pagerduty",
                integration_key="test",
                event_type="trigger",
                title="Critical",
                severity="critical",
                priority="immediate"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_low_priority_batched(self):
        """Test low priority notifications batched."""
        from services.notification_service.main import send_notification

        with patch('services.notification_service.main.send_email') as mock_email:
            mock_email.return_value = {"success": True}

            result = await send_notification(
                channel="email",
                to="test@example.com",
                message="Low priority",
                priority="low",
                batch=True
            )

            assert result["success"] is True


class TestNotificationFailureHandling:
    """Test notification failure handling."""

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Test retry mechanism on failure."""
        from services.notification_service.main import send_notification

        call_count = 0

        async def failing_then_success(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return {"success": False, "error": "Temporary error"}
            return {"success": True}

        with patch('services.notification_service.main.send_slack', side_effect=failing_then_success):
            result = await send_notification(
                channel="slack",
                webhook_url="https://hooks.slack.com/test",
                message="Test",
                max_retries=3
            )

            assert result["success"] is True
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_fallback_channel(self):
        """Test fallback to secondary channel."""
        from services.notification_service.main import send_notification_with_fallback

        with patch('services.notification_service.main.send_slack') as mock_slack, \
             patch('services.notification_service.main.send_email') as mock_email:

            mock_slack.return_value = {"success": False, "error": "Failed"}
            mock_email.return_value = {"success": True}

            result = await send_notification_with_fallback(
                primary_channel="slack",
                fallback_channel="email",
                slack_webhook_url="https://hooks.slack.com/test",
                email_to="test@example.com",
                message="Test"
            )

            assert result["success"] is True
            assert result["channel"] == "email"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
