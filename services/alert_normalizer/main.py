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
Alert Normalizer Service - Normalizes alerts from different sources.

This service consumes raw alerts from the message queue, normalizes them
to a standard format, extracts IOCs, and publishes normalized alerts.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uuid
import asyncio
import re
import hashlib
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

from shared.models import (
    SecurityAlert,
    AlertType,
    Severity,
    SuccessResponse,
    ResponseMeta,
)
from shared.messaging import MessagePublisher, MessageConsumer
from shared.database import get_database_manager, DatabaseManager
from shared.utils import get_logger, Config

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None

# Deduplication cache (in-memory, use Redis in production)
processed_alerts_cache: Set[str] = set()
CACHE_MAX_SIZE = 10000


# =============================================================================
# Field Mapping Functions
# =============================================================================

# Field mappings for different alert sources
FIELD_MAPPINGS = {
    # Splunk format
    "splunk": {
        "alert_id": ["result_id", "alert_id", "id"],
        "timestamp": ["_time", "timestamp", "time"],
        "alert_type": ["category", "alert_type", "type"],
        "severity": ["severity", "priority", "level"],
        "description": ["message", "description", "title"],
        "source_ip": ["src_ip", "source_ip", "src"],
        "target_ip": ["dest_ip", "destination_ip", "dest", "dst_ip"],
        "file_hash": ["file_hash", "hash", "md5", "sha256"],
        "url": ["url", "uri", "domain"],
        "asset_id": ["asset", "host", "hostname"],
        "user_id": ["user", "username", "account"],
    },
    # QRadar format
    "qradar": {
        "alert_id": ["alert_id", "id"],
        "timestamp": ["start_time", "timestamp"],
        "alert_type": ["alert_type", "category"],
        "severity": ["severity", "magnitude"],
        "description": ["description", "rule_name"],
        "source_ip": ["source_ip", "src_address"],
        "target_ip": ["destination_ip", "dest_address"],
        "asset_id": ["asset_id", "host_name"],
    },
    # Default/generic format
    "default": {
        "alert_id": ["alert_id", "id"],
        "timestamp": ["timestamp", "time", "date"],
        "alert_type": ["alert_type", "type", "category"],
        "severity": ["severity", "level", "priority"],
        "description": ["description", "message", "title"],
        "source_ip": ["source_ip", "src", "src_ip"],
        "target_ip": ["target_ip", "dest", "dst_ip", "destination_ip"],
        "file_hash": ["file_hash", "hash"],
        "url": ["url"],
        "asset_id": ["asset_id", "asset", "host"],
        "user_id": ["user_id", "user", "username"],
    },
}


def map_field(raw_alert: dict, source_type: str, target_field: str) -> Any:
    """
    Map a field from raw alert to standard format.

    Args:
        raw_alert: Raw alert dictionary
        source_type: Source system type (splunk, qradar, default)
        target_field: Target field name in standard format

    Returns:
        Mapped field value or None
    """
    mappings = FIELD_MAPPINGS.get(source_type, FIELD_MAPPINGS["default"])
    possible_fields = mappings.get(target_field, [target_field])

    for field in possible_fields:
        if field in raw_alert and raw_alert[field] is not None:
            return raw_alert[field]

    return None


# =============================================================================
# IOC Extraction Functions
# =============================================================================


def extract_iocs(raw_alert: dict) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IOCs) from alert.

    Args:
        raw_alert: Raw alert data

    Returns:
        Dictionary of IOC type to list of values
    """
    iocs = {
        "ip_addresses": [],
        "file_hashes": [],
        "urls": [],
        "domains": [],
        "email_addresses": [],
    }

    # Convert to text for scanning
    alert_text = str(raw_alert)

    # Extract IP addresses
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ip_matches = re.findall(ip_pattern, alert_text)
    for ip in ip_matches:
        # Validate IP range
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            iocs["ip_addresses"].append(ip)

    # Extract file hashes (MD5, SHA1, SHA256)
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    if re.search(md5_pattern, alert_text):
        iocs["file_hashes"].extend(re.findall(md5_pattern, alert_text))
    if re.search(sha1_pattern, alert_text):
        iocs["file_hashes"].extend(re.findall(sha1_pattern, alert_text))
    if re.search(sha256_pattern, alert_text):
        iocs["file_hashes"].extend(re.findall(sha256_pattern, alert_text))

    # Remove duplicates
    for key in iocs:
        iocs[key] = list(set(iocs[key]))

    return iocs


# =============================================================================
# Alert Deduplication
# =============================================================================


def generate_alert_fingerprint(alert: dict) -> str:
    """
    Generate fingerprint for alert deduplication.

    Args:
        alert: Alert data

    Returns:
        SHA256 hash fingerprint
    """
    # Key fields for deduplication
    key_fields = [
        alert.get("alert_type", ""),
        alert.get("source_ip", ""),
        alert.get("target_ip", ""),
        alert.get("file_hash", ""),
        alert.get("url", ""),
        alert.get("asset_id", ""),
        alert.get("user_id", ""),
    ]

    # Create fingerprint string
    fingerprint_str = "|".join(str(f) for f in key_fields if f)

    # Generate hash
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


def is_duplicate_alert(alert: dict) -> bool:
    """
    Check if alert is a duplicate.

    Args:
        alert: Alert data

    Returns:
        True if duplicate, False otherwise
    """
    fingerprint = generate_alert_fingerprint(alert)

    if fingerprint in processed_alerts_cache:
        logger.debug(f"Duplicate alert detected: {fingerprint[:16]}")
        return True

    # Add to cache
    processed_alerts_cache.add(fingerprint)

    # Manage cache size
    if len(processed_alerts_cache) > CACHE_MAX_SIZE:
        # Remove oldest entries (simplified: clear half the cache)
        processed_alerts_cache.clear()

    return False


# =============================================================================
# Alert Normalization
# =============================================================================


def normalize_alert(raw_alert: dict, source_type: str = "default") -> SecurityAlert:
    """
    Normalize alert from source system to standard format.

    Args:
        raw_alert: Raw alert data
        source_type: Source system type

    Returns:
        Normalized SecurityAlert

    Raises:
        ValueError: If validation fails
    """
    try:
        # Extract and map fields
        alert_id = map_field(raw_alert, source_type, "alert_id") or f"AUTO-{uuid.uuid4()}"
        timestamp_str = map_field(raw_alert, source_type, "timestamp")
        alert_type_str = map_field(raw_alert, source_type, "alert_type")
        severity_str = map_field(raw_alert, source_type, "severity")
        description = map_field(raw_alert, source_type, "description")
        source_ip = map_field(raw_alert, source_type, "source_ip")
        target_ip = map_field(raw_alert, source_type, "target_ip")
        file_hash = map_field(raw_alert, source_type, "file_hash")
        url = map_field(raw_alert, source_type, "url")
        asset_id = map_field(raw_alert, source_type, "asset_id")
        user_id = map_field(raw_alert, source_type, "user_id")

        # Parse timestamp
        if timestamp_str:
            if isinstance(timestamp_str, str):
                # Try common timestamp formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S%z",
                ]:
                    try:
                        timestamp = datetime.strptime(timestamp_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    # If all formats fail, use current time
                    timestamp = datetime.utcnow()
            elif isinstance(timestamp_str, datetime):
                timestamp = timestamp_str
            else:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        # Parse alert type
        if alert_type_str:
            alert_type = AlertType.from_string(str(alert_type_str))
        else:
            alert_type = AlertType.OTHER

        # Parse severity
        if severity_str:
            severity_str = str(severity_str).lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)
        else:
            severity = Severity.MEDIUM

        # Validate required fields
        if not description:
            description = f"Alert from {source_type}"

        # Validate IP addresses
        if source_ip:
            # Basic IP validation
            ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
            if not re.match(ip_pattern, str(source_ip)):
                source_ip = None

        if target_ip:
            if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", str(target_ip)):
                target_ip = None

        # Validate file hash format
        if file_hash:
            hash_len = len(str(file_hash))
            if hash_len not in [32, 40, 64]:
                file_hash = None

        # Create normalized alert
        normalized_alert = SecurityAlert(
            alert_id=str(alert_id),
            timestamp=timestamp,
            alert_type=alert_type,
            severity=severity,
            description=str(description),
            source_ip=source_ip,
            target_ip=target_ip,
            file_hash=file_hash,
            url=url,
            asset_id=asset_id,
            user_id=user_id,
            raw_data=raw_alert,  # Preserve original data
            normalized_data={
                "source_type": source_type,
                "normalized_at": datetime.utcnow().isoformat(),
            },
        )

        logger.debug(
            "Alert normalized successfully",
            extra={
                "alert_id": normalized_alert.alert_id,
                "source_type": source_type,
                "alert_type": normalized_alert.alert_type.value,
            },
        )

        return normalized_alert

    except Exception as e:
        logger.error(f"Failed to normalize alert: {e}", exc_info=True)
        raise ValueError(f"Alert normalization failed: {str(e)}")


# =============================================================================
# FastAPI Application
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, publisher, consumer

    logger.info("Starting Alert Normalizer Service")

    try:
        # Initialize database
        db_manager = get_database_manager()
        await db_manager.initialize()
        logger.info("✓ Database connected")

        # Initialize message publisher
        publisher = MessagePublisher(config.rabbitmq_url)
        await publisher.connect()
        logger.info("✓ Message publisher connected")

        # Initialize message consumer
        consumer = MessageConsumer(config.rabbitmq_url, "alert.raw")
        await consumer.connect()
        logger.info("✓ Message consumer connected")

        logger.info("✓ Alert Normalizer Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        logger.info("Shutting down Alert Normalizer Service")

        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")

        if publisher:
            await publisher.close()
            logger.info("✓ Message publisher closed")

        if db_manager:
            await db_manager.close()
            logger.info("✓ Database connection closed")

        logger.info("✓ Alert Normalizer Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Alert Normalizer API",
    description="Normalizes security alerts from different sources",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Background Task: Message Consumer
# =============================================================================


async def consume_alerts():
    """Consume raw alerts from queue and normalize them."""

    async def process_message(message: dict):
        try:
            payload = message.get("payload", {})
            message_id = message.get("message_id", "unknown")

            logger.info(f"Processing message {message_id}")

            # Detect source type
            source_type = payload.get("source_type", "default")

            # Check for duplicates
            if is_duplicate_alert(payload):
                logger.info(f"Duplicate alert skipped: {message_id}")
                return

            # Normalize alert
            normalized = normalize_alert(payload, source_type)

            # Extract IOCs
            iocs = extract_iocs(payload)

            # Add IOCs to normalized data
            if iocs:
                normalized.normalized_data["iocs"] = iocs

            # Publish normalized alert
            normalized_message = {
                "message_id": str(uuid.uuid4()),
                "message_type": "alert.normalized",
                "correlation_id": normalized.alert_id,
                "original_message_id": message_id,
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0",
                "source_type": source_type,
                "payload": normalized.model_dump(),
            }

            await publisher.publish("alert.normalized", normalized_message)

            logger.info(
                "Alert normalized successfully",
                extra={
                    "message_id": message_id,
                    "alert_id": normalized.alert_id,
                    "source_type": source_type,
                    "alert_type": normalized.alert_type.value,
                },
            )

        except ValueError as e:
            logger.warning(f"Validation error: {e}")
            # TODO: Send to dead letter queue
        except Exception as e:
            logger.error(f"Normalization failed: {e}", exc_info=True)
            # TODO: Send to dead letter queue

    # Start consuming
    await consumer.consume(process_message)


# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    try:
        return {
            "status": "healthy",
            "service": "alert-normalizer",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "database": "connected" if db_manager else "disconnected",
                "message_queue_consumer": "connected" if consumer else "disconnected",
                "message_queue_publisher": "connected" if publisher else "disconnected",
                "cache_size": len(processed_alerts_cache),
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "service": "alert-normalizer",
            "error": str(e),
        }


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get normalization metrics."""
    return {
        "processed_alerts": len(processed_alerts_cache),
        "cache_size": len(processed_alerts_cache),
        "cache_max_size": CACHE_MAX_SIZE,
        "service": "alert-normalizer",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level=config.log_level.lower(),
    )
