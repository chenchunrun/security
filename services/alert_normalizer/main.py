"""Alert Normalizer Service - Normalizes alerts from different sources."""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uuid

from shared.models import SecurityAlert, SuccessResponse, ResponseMeta
from shared.messaging import MessagePublisher, MessageConsumer
from shared.utils import get_logger, Config
from shared.database import get_database_manager, DatabaseManager

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None


@app.on_event("startup")
async def startup():
    global db_manager, publisher, consumer
    db_manager = get_database_manager()
    await db_manager.initialize()

    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "alert.raw")
    await consumer.connect()

    # Start consuming in background
    asyncio.create_task(consume_alerts())


@app.on_event("shutdown")
async def shutdown():
    await consumer.close()
    await publisher.close()
    await db_manager.close()


app = FastAPI(title="Alert Normalizer", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def consume_alerts():
    """Consume raw alerts from queue."""
    async def process_message(message: dict):
        try:
            # Normalize alert
            normalized = normalize_alert(message["payload"])

            # Publish normalized alert
            await publisher.publish("alert.normalized", {
                "message_id": str(uuid.uuid4()),
                "message_type": "alert.normalized",
                "payload": normalized.model_dump(),
                "timestamp": datetime.utcnow().isoformat(),
            })

            logger.info(f"Normalized alert {normalized.alert_id}")

        except Exception as e:
            logger.error(f"Normalization failed: {e}")

    await consumer.consume(process_message)


def normalize_alert(raw_alert: dict) -> SecurityAlert:
    """Normalize alert to standard format."""
    # TODO: Implement source-specific normalization logic
    # For now, just validate and return
    return SecurityAlert(**raw_alert)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "alert-normalizer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.host, port=config.port)
