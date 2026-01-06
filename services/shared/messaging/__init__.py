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
Shared messaging layer for RabbitMQ integration.

Provides message publishing and consuming utilities.
"""

from typing import Optional, Dict, Any, Callable
from aio_pika import connect_robust, Message, ExchangeType, RobustConnection
from aio_pika.abc import AbstractChannel, AbstractQueue
import json
import asyncio
from shared.utils.logger import get_logger

logger = get_logger(__name__)


class MessagePublisher:
    """Message publisher for RabbitMQ."""

    def __init__(self, amqp_url: str):
        """
        Initialize publisher.

        Args:
            amqp_url: RabbitMQ connection URL
        """
        self.amqp_url = amqp_url
        self.connection: Optional[RobustConnection] = None
        self.channel: Optional[AbstractChannel] = None

    async def connect(self):
        """Connect to RabbitMQ."""
        self.connection = await connect_robust(self.amqp_url)
        self.channel = await self.connection.channel()
        logger.info("Connected to RabbitMQ")

    async def publish(
        self,
        queue_name: str,
        message: Dict[str, Any],
        persistent: bool = True,
    ) -> None:
        """
        Publish message to queue.

        Args:
            queue_name: Target queue name
            message: Message payload
            persistent: Whether to persist message
        """
        if not self.connection:
            await self.connect()

        # Declare queue
        await self.channel.declare_queue(queue_name, durable=True)

        # Create message
        message_body = json.dumps(message).encode()
        msg = Message(message_body, delivery_mode=2 if persistent else 1)

        # Publish
        await self.channel.default_exchange.publish(msg, routing_key=queue_name)

        logger.info(
            f"Published message to {queue_name}",
            extra={
                "queue": queue_name,
                "message_id": message.get("message_id"),
            },
        )

    async def close(self):
        """Close connection."""
        if self.connection:
            await self.connection.close()
            logger.info("RabbitMQ connection closed")


class MessageConsumer:
    """Message consumer for RabbitMQ."""

    def __init__(
        self,
        amqp_url: str,
        queue_name: str,
        auto_ack: bool = False,
        prefetch_count: int = 10,
    ):
        """
        Initialize consumer.

        Args:
            amqp_url: RabbitMQ connection URL
            queue_name: Queue to consume from
            auto_ack: Auto-acknowledge messages
            prefetch_count: Prefetch count
        """
        self.amqp_url = amqp_url
        self.queue_name = queue_name
        self.auto_ack = auto_ack
        self.prefetch_count = prefetch_count
        self.connection: Optional[RobustConnection] = None
        self.channel: Optional[AbstractChannel] = None

    async def connect(self):
        """Connect to RabbitMQ."""
        self.connection = await connect_robust(self.amqp_url)
        self.channel = await self.connection.channel()
        await self.channel.set_qos(prefetch_count=self.prefetch_count)

        # Declare queue
        await self.channel.declare_queue(self.queue_name, durable=True)

        logger.info(f"Connected to RabbitMQ, consuming from {self.queue_name}")

    async def consume(self, callback: Callable[[Dict[str, Any]], Any]):
        """
        Start consuming messages.

        Args:
            callback: Async callback function for message processing
        """
        if not self.connection:
            await self.connect()

        async with self.channel.iterator(self.queue_name, no_ack=self.auto_ack) as queue_iter:
            async for message in queue_iter:
                try:
                    # Parse message
                    body = json.loads(message.body.decode())
                    await callback(body)

                    # Acknowledge
                    if not self.auto_ack:
                        await message.ack()

                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    if not self.auto_ack:
                        await message.nack(requeue=False)

    async def close(self):
        """Close connection."""
        if self.connection:
            await self.connection.close()


# Queue definitions
QUEUES = {
    "alert.raw": {"type": "direct", "durable": True},
    "alert.normalized": {"type": "direct", "durable": True},
    "alert.enriched": {"type": "direct", "durable": True},
    "alert.result": {"type": "direct", "durable": True},
    "notifications": {"type": "fanout", "durable": True},
}

# Alias for backwards compatibility
QUEUE_DEFINITIONS = QUEUES

__all__ = [
    "MessagePublisher",
    "MessageConsumer",
    "QUEUES",
    "QUEUE_DEFINITIONS",
]
