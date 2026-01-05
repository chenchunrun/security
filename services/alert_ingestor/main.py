"""
Alert Ingestor Service - Main Application

Receives security alerts from multiple sources and publishes to message queue.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uuid
from datetime import datetime
import asyncio
from contextlib import asynccontextmanager

from shared.models import (
    SecurityAlert,
    AlertBatch,
    SuccessResponse,
    ErrorResponse,
    ResponseMeta,
)
from shared.messaging import MessagePublisher
from shared.database import get_database_manager, DatabaseManager
from shared.utils import get_logger, Config
from shared.errors import ValidationError

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
message_publisher: MessagePublisher = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, message_publisher

    # Startup
    logger.info("Starting Alert Ingestor Service")

    # Initialize database
    db_manager = get_database_manager()
    await db_manager.initialize()
    logger.info("Database connected")

    # Initialize message publisher
    message_publisher = MessagePublisher(config.rabbitmq_url)
    await message_publisher.connect()
    logger.info("Message publisher connected")

    yield

    # Shutdown
    logger.info("Shutting down Alert Ingestor Service")
    await message_publisher.close()
    await db_manager.close()


# Create FastAPI app
app = FastAPI(
    title="Alert Ingestor API",
    description="Security alert ingestion service",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    try:
        # Check database
        db_health = await db_manager.health_check()

        return {
            "status": "healthy",
            "service": "alert-ingestor",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "database": db_health,
                "message_queue": "connected" if message_publisher else "disconnected",
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "alert-ingestor",
                "error": str(e),
            },
        )


# API Routes
@app.post(
    "/api/v1/alerts",
    response_model=SuccessResponse[dict],
    tags=["Alerts"],
    summary="Ingest a single alert",
)
async def ingest_alert(alert: SecurityAlert):
    """
    Ingest a single security alert.

    Validates the alert and publishes it to the message queue for processing.

    Args:
        alert: Security alert data

    Returns:
        Ingestion confirmation with ingestion_id
    """
    try:
        # Generate ingestion ID
        ingestion_id = str(uuid.uuid4())

        # Create message
        message = {
            "message_id": ingestion_id,
            "message_type": "alert.raw",
            "correlation_id": alert.alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0",
            "payload": alert.model_dump(),
        }

        # Publish to message queue
        await message_publisher.publish("alert.raw", message)

        # Log
        logger.info(
            "Alert ingested",
            extra={
                "ingestion_id": ingestion_id,
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
            },
        )

        # Return response
        return SuccessResponse(
            data={
                "ingestion_id": ingestion_id,
                "alert_id": alert.alert_id,
                "status": "queued",
                "message": "Alert queued for processing",
            },
            meta=ResponseMeta(
                timestamp=datetime.utcnow(),
                request_id=ingestion_id,
            ),
        )

    except Exception as e:
        logger.error(f"Failed to ingest alert: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest alert: {str(e)}",
        )


@app.post(
    "/api/v1/alerts/batch",
    response_model=SuccessResponse[dict],
    tags=["Alerts"],
    summary="Ingest multiple alerts",
)
async def ingest_alert_batch(batch: AlertBatch):
    """
    Ingest multiple security alerts in batch.

    Args:
        batch: Batch of alerts (max 100)

    Returns:
        Batch ingestion confirmation
    """
    try:
        # Generate batch ID if not provided
        if not batch.batch_id:
            batch.batch_id = f"BATCH-{uuid.uuid4()}"

        # Process each alert
        ingestion_ids = []
        errors = []

        for alert in batch.alerts:
            try:
                ingestion_id = str(uuid.uuid4())
                message = {
                    "message_id": ingestion_id,
                    "message_type": "alert.raw",
                    "correlation_id": alert.alert_id,
                    "batch_id": batch.batch_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "payload": alert.model_dump(),
                }

                await message_publisher.publish("alert.raw", message)
                ingestion_ids.append(ingestion_id)

            except Exception as e:
                logger.error(f"Failed to ingest alert {alert.alert_id}: {e}")
                errors.append({"alert_id": alert.alert_id, "error": str(e)})

        # Log
        logger.info(
            f"Batch ingested: {batch.batch_id}",
            extra={
                "batch_id": batch.batch_id,
                "total": len(batch.alerts),
                "successful": len(ingestion_ids),
                "failed": len(errors),
            },
        )

        # Return response
        return SuccessResponse(
            data={
                "batch_id": batch.batch_id,
                "total": len(batch.alerts),
                "successful": len(ingestion_ids),
                "failed": len(errors),
                "ingestion_ids": ingestion_ids,
                "errors": errors if errors else None,
            },
            meta=ResponseMeta(
                timestamp=datetime.utcnow(),
                request_id=batch.batch_id,
            ),
        )

    except Exception as e:
        logger.error(f"Failed to ingest batch: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest batch: {str(e)}",
        )


@app.get(
    "/api/v1/alerts/{alert_id}",
    response_model=SuccessResponse[dict],
    tags=["Alerts"],
    summary="Get alert status",
)
async def get_alert_status(alert_id: str):
    """
    Get alert processing status.

    Args:
        alert_id: Alert identifier

    Returns:
        Alert status information
    """
    # TODO: Implement actual status lookup from database
    return SuccessResponse(
        data={
            "alert_id": alert_id,
            "status": "processing",
            "message": "Alert is being processed",
        },
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level=config.log_level.lower(),
    )
