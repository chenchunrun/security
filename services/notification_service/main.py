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

"""Notification Service - Sends notifications via multiple channels."""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
import uuid
from typing import Dict, Any, Optional, List
from enum import Enum
import asyncio
import httpx

from shared.models import SuccessResponse, ResponseMeta
from shared.messaging import MessageConsumer, MessagePublisher
from shared.utils import get_logger, Config
from shared.database import get_database_manager, DatabaseManager

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None
consumer: MessageConsumer = None
publisher: MessagePublisher = None


class NotificationChannel(str, Enum):
    """Notification channels."""

    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    WEBHOOK = "webhook"
    IN_APP = "in_app"


class NotificationPriority(str, Enum):
    """Notification priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, consumer, publisher

    logger.info("Starting Notification service...")

    # Initialize database
    db_manager = get_database_manager()
    await db_manager.initialize()

    # Initialize messaging
    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "notifications.send")
    await consumer.connect()

    # Start consuming notification requests
    asyncio.create_task(consume_notifications())

    logger.info("Notification service started successfully")

    yield

    # Cleanup
    await consumer.close()
    await publisher.close()
    await db_manager.close()
    logger.info("Notification service stopped")


app = FastAPI(
    title="Notification Service",
    description="Sends notifications via multiple channels",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Notification channel implementations

async def send_email(
    recipient: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None
) -> Dict[str, Any]:
    """Send email notification."""
    try:
        # TODO: Integrate with email service (SendGrid, AWS SES, SMTP)
        logger.info(f"Sending email to {recipient}: {subject}")

        # Mock implementation
        await asyncio.sleep(0.5)

        return {
            "success": True,
            "channel": "email",
            "recipient": recipient,
            "message_id": f"email-{uuid.uuid4()}"
        }

    except Exception as e:
        logger.error(f"Failed to send email: {e}", exc_info=True)
        return {
            "success": False,
            "channel": "email",
            "error": str(e)
        }


async def send_slack(
    webhook_url: str,
    message: str,
    channel: Optional[str] = None,
    username: Optional[str] = None
) -> Dict[str, Any]:
    """Send Slack notification."""
    try:
        payload = {
            "text": message,
            "username": username or "Security Triage Bot"
        }

        if channel:
            payload["channel"] = channel

        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=payload,
                timeout=10.0
            )
            response.raise_for_status()

        logger.info(f"Slack message sent to {channel or 'default channel'}")

        return {
            "success": True,
            "channel": "slack",
            "webhook_url": webhook_url
        }

    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}", exc_info=True)
        return {
            "success": False,
            "channel": "slack",
            "error": str(e)
        }


async def send_webhook(
    webhook_url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Send webhook notification."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=payload,
                headers=headers or {},
                timeout=10.0
            )
            response.raise_for_status()

        logger.info(f"Webhook sent to {webhook_url}")

        return {
            "success": True,
            "channel": "webhook",
            "webhook_url": webhook_url,
            "status_code": response.status_code
        }

    except Exception as e:
        logger.error(f"Failed to send webhook: {e}", exc_info=True)
        return {
            "success": False,
            "channel": "webhook",
            "error": str(e)
        }


async def send_notification(
    channel: NotificationChannel,
    recipient: str,
    subject: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Send notification via specified channel."""
    try:
        if channel == NotificationChannel.EMAIL:
            return await send_email(recipient, subject, message)

        elif channel == NotificationChannel.SLACK:
            return await send_slack(recipient, message)

        elif channel == NotificationChannel.WEBHOOK:
            return await send_webhook(
                recipient,
                data or {"message": message, "subject": subject}
            )

        elif channel == NotificationChannel.SMS:
            # TODO: Implement SMS (Twilio, AWS SNS)
            logger.info(f"SMS notification to {recipient}: {message}")
            return {"success": True, "channel": "sms"}

        elif channel == NotificationChannel.IN_APP:
            # TODO: Store in-app notification in database
            logger.info(f"In-app notification for {recipient}: {message}")
            return {"success": True, "channel": "in_app"}

        else:
            raise ValueError(f"Unsupported channel: {channel}")

    except Exception as e:
        logger.error(f"Failed to send notification: {e}", exc_info=True)
        return {
            "success": False,
            "channel": channel.value,
            "error": str(e)
        }


async def consume_notifications():
    """Consume notification requests from message queue."""
    async def process_message(message: dict):
        try:
            payload = message["payload"]
            channel = NotificationChannel(payload.get("channel", "email"))
            recipient = payload.get("recipient")
            subject = payload.get("subject", "")
            message_text = payload.get("message", "")
            priority = NotificationPriority(payload.get("priority", "normal"))
            data = payload.get("data")

            if not recipient or not message_text:
                logger.error("Missing required fields in notification message")
                return

            # Send notification
            result = await send_notification(
                channel,
                recipient,
                subject,
                message_text,
                priority,
                data
            )

            if result.get("success"):
                logger.info(f"Notification sent successfully via {channel.value}")
            else:
                logger.error(f"Notification failed: {result.get('error')}")

        except Exception as e:
            logger.error(f"Failed to process notification: {e}", exc_info=True)

    await consumer.consume(process_message)


# API Endpoints

@app.post("/api/v1/notifications/send", response_model=Dict[str, Any])
async def send_notification_api(
    channel: NotificationChannel,
    recipient: str,
    subject: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    data: Optional[Dict[str, Any]] = None,
    background_tasks: BackgroundTasks = None
):
    """
    Send notification via API.

    Args:
        channel: Notification channel
        recipient: Recipient address/webhook URL
        subject: Notification subject/title
        message: Notification message body
        priority: Notification priority
        data: Additional data for the notification
    """
    try:
        # Send notification
        result = await send_notification(
            channel,
            recipient,
            subject,
            message,
            priority,
            data
        )

        return {
            "success": result.get("success", False),
            "data": result,
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4())
            }
        }

    except Exception as e:
        logger.error(f"Failed to send notification: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send notification: {str(e)}"
        )


@app.post("/api/v1/notifications/broadcast", response_model=Dict[str, Any])
async def broadcast_notification(
    channel: NotificationChannel,
    recipients: List[str],
    subject: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    background_tasks: BackgroundTasks = None
):
    """Broadcast notification to multiple recipients."""
    try:
        results = []

        for recipient in recipients:
            result = await send_notification(
                channel,
                recipient,
                subject,
                message,
                priority
            )
            results.append(result)

        successful = sum(1 for r in results if r.get("success"))
        total = len(results)

        return {
            "success": successful > 0,
            "data": {
                "total": total,
                "successful": successful,
                "failed": total - successful,
                "results": results
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4())
            }
        }

    except Exception as e:
        logger.error(f"Failed to broadcast notification: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to broadcast notification: {str(e)}"
        )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "notification-service",
        "timestamp": datetime.utcnow().isoformat(),
        "channels": [c.value for c in NotificationChannel]
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
