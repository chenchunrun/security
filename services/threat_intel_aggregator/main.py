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
Threat Intel Aggregator Service - Aggregates threat intelligence from multiple sources.

This service queries multiple threat intelligence sources for IOCs:
- VirusTotal (IPs, hashes, URLs)
- Abuse.ch (SSLBL, URLhaus)
- AlienVault OTX
- Custom threat feeds

Aggregates results and provides a consolidated threat score.
"""

import asyncio
import hashlib
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from shared.database import DatabaseManager, get_database_manager
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import SecurityAlert
from shared.utils import Config, get_logger

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None

# Cache for threat intel (in-memory, use Redis in production)
threat_cache: Dict[str, tuple] = {}  # key: (data, expiry_time)
CACHE_TTL_SECONDS = 86400  # 24 hours


# =============================================================================
# Threat Intel Sources Configuration
# =============================================================================


class ThreatIntelSource:
    """Base class for threat intelligence sources."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for an IP address."""
        raise NotImplementedError

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for a file hash."""
        raise NotImplementedError

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for a URL."""
        raise NotImplementedError


class VirusTotalSource(ThreatIntelSource):
    """VirusTotal threat intelligence source."""

    def __init__(self, api_key: str):
        super().__init__("VirusTotal")
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.enabled = bool(api_key and api_key != "your_vt_key")

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for IP reputation."""
        if not self.enabled:
            return None

        try:
            params = {"ip": ip, "apikey": self.api_key}
            url = f"{self.base_url}/ip-address/report"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_ip_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None

        except asyncio.TimeoutError:
            logger.error(f"VirusTotal timeout for IP {ip}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for IP {ip}: {e}")
            return None

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for file hash."""
        if not self.enabled:
            return None

        try:
            params = {"resource": file_hash, "apikey": self.api_key}
            url = f"{self.base_url}/file/report"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_hash_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None

        except asyncio.TimeoutError:
            logger.error(f"VirusTotal timeout for hash {file_hash}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for hash {file_hash}: {e}")
            return None

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for URL."""
        if not self.enabled:
            return None

        try:
            params = {"resource": url, "apikey": self.api_key}
            api_url = f"{self.base_url}/url/report"

            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_url_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None

        except asyncio.TimeoutError:
            logger.error(f"VirusTotal timeout for URL {url}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for URL {url}: {e}")
            return None

    def _parse_ip_response(self, data: dict) -> Dict[str, Any]:
        """Parse VirusTotal IP response."""
        return {
            "source": "VirusTotal",
            "detected": data.get("detected_urls", []) > 0,
            "positives": len(data.get("detected_urls", [])),
            "country": data.get("country"),
            "as_owner": data.get("as_owner"),
            "response_code": data.get("response_code"),
        }

    def _parse_hash_response(self, data: dict) -> Dict[str, Any]:
        """Parse VirusTotal hash response."""
        return {
            "source": "VirusTotal",
            "detected": data.get("response_code") == 1,
            "positives": data.get("positives", 0),
            "total": data.get("total", 0),
            "scan_date": data.get("scan_date"),
        }

    def _parse_url_response(self, data: dict) -> Dict[str, Any]:
        """Parse VirusTotal URL response."""
        return {
            "source": "VirusTotal",
            "detected": data.get("response_code") == 1,
            "positives": data.get("positives", 0),
            "total": data.get("total", 0),
            "scan_date": data.get("scan_date"),
        }


class AbuseCHSource(ThreatIntelSource):
    """Abuse.ch threat intelligence source."""

    def __init__(self, api_key: str = None):
        super().__init__("Abuse.ch")
        self.api_key = api_key
        self.base_url = "https://urlhaus-api.abuse.ch/v1"
        self.enabled = True  # Abuse.ch has free public API

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query Abuse.ch for file hash."""
        if not self.enabled:
            return None

        try:
            params = {"sha256_hash": file_hash}
            url = f"{self.base_url}/payload/"

            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_hash_response(data)
                    else:
                        return None

        except Exception as e:
            logger.error(f"Abuse.ch query failed for hash {file_hash}: {e}")
            return None

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query Abuse.ch for URL."""
        if not self.enabled:
            return None

        try:
            params = {"url": url}
            api_url = f"{self.base_url}/url/"

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, data=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_url_response(data)
                    else:
                        return None

        except Exception as e:
            logger.error(f"Abuse.ch query failed for URL {url}: {e}")
            return None

    def _parse_hash_response(self, data: dict) -> Dict[str, Any]:
        """Parse Abuse.ch hash response."""
        if data.get("query_status") == "ok":
            return {
                "source": "Abuse.ch",
                "detected": True,
                "threat_type": data.get("threat_type"),
                "tags": data.get("tags", []),
            }
        return {
            "source": "Abuse.ch",
            "detected": False,
        }

    def _parse_url_response(self, data: dict) -> Dict[str, Any]:
        """Parse Abuse.ch URL response."""
        if data.get("query_status") == "ok":
            return {
                "source": "Abuse.ch",
                "detected": True,
                "threat_type": data.get("threat_type"),
                "url_status": data.get("url_status"),
            }
        return {
            "source": "Abuse.ch",
            "detected": False,
        }


class CustomThreatFeed(ThreatIntelSource):
    """Custom threat intelligence feed (internal blocklist)."""

    def __init__(self):
        super().__init__("CustomFeed")
        self.enabled = True

        # Internal blocklist (example data)
        self.blocklist_ips = set()
        self.blocklist_hashes = set()
        self.blocklist_urls = set()

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query internal IP blocklist."""
        if not self.enabled or ip not in self.blocklist_ips:
            return None

        return {
            "source": "CustomFeed",
            "detected": True,
            "list_type": "blocked",
        }

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query internal hash blocklist."""
        if not self.enabled or file_hash not in self.blocklist_hashes:
            return None

        return {
            "source": "CustomFeed",
            "detected": True,
            "list_type": "blocked",
        }

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query internal URL blocklist."""
        if not self.enabled or url not in self.blocklist_urls:
            return None

        return {
            "source": "CustomFeed",
            "detected": True,
            "list_type": "blocked",
        }


# Initialize threat intel sources
threat_sources: List[ThreatIntelSource] = []


def init_threat_sources():
    """Initialize threat intelligence sources from config."""
    global threat_sources

    # VirusTotal (requires API key)
    vt_api_key = config.get("virustotal_api_key", "your_vt_key")
    threat_sources.append(VirusTotalSource(vt_api_key))

    # Abuse.ch (free public API)
    threat_sources.append(AbuseCHSource())

    # Custom internal feed
    threat_sources.append(CustomThreatFeed())

    logger.info(f"Initialized {len(threat_sources)} threat intel sources")


# =============================================================================
# Threat Intelligence Query Functions
# =============================================================================


async def query_threat_intel(
    ip: str = None, file_hash: str = None, url: str = None
) -> Dict[str, Any]:
    """
    Query multiple threat intelligence sources.

    Args:
        ip: IP address to query
        file_hash: File hash to query
        url: URL to query

    Returns:
        Aggregated threat intelligence
    """
    results = {
        "sources_queried": 0,
        "sources_found": 0,
        "threat_score": 0.0,  # 0-100, higher is more malicious
        "indicators": [],
    }

    # Query all sources for the given IOC
    tasks = []

    if ip:
        for source in threat_sources:
            if source.enabled:
                tasks.append(source.query_ip(ip))

    if file_hash:
        for source in threat_sources:
            if source.enabled:
                tasks.append(source.query_hash(file_hash))

    if url:
        for source in threat_sources:
            if source.enabled:
                tasks.append(source.query_url(url))

    # Execute queries concurrently
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Process responses
    for response in responses:
        if isinstance(response, Exception):
            logger.error(f"Threat intel query error: {response}")
            continue

        if response:
            results["sources_queried"] += 1
            results["indicators"].append(response)

            if response.get("detected"):
                results["sources_found"] += 1

    # Calculate threat score
    if results["sources_queried"] > 0:
        detected_ratio = results["sources_found"] / results["sources_queried"]
        results["threat_score"] = detected_ratio * 100

    return results


# =============================================================================
# Alert Enrichment with Threat Intel
# =============================================================================


async def enrich_with_threat_intel(alert: SecurityAlert) -> Dict[str, Any]:
    """
    Enrich alert with threat intelligence.

    Args:
        alert: SecurityAlert object

    Returns:
        Threat intelligence enrichment
    """
    enrichment = {
        "alert_id": alert.alert_id,
        "enriched_at": datetime.utcnow().isoformat(),
        "threat_intel": {},
    }

    # Query IPs
    if alert.source_ip:
        cache_key = f"threat_ip:{alert.source_ip}"
        cached = check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["source_ip"] = cached
        else:
            result = await query_threat_intel(ip=alert.source_ip)
            set_cache(cache_key, result)
            enrichment["threat_intel"]["source_ip"] = result

    if alert.target_ip:
        cache_key = f"threat_ip:{alert.target_ip}"
        cached = check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["target_ip"] = cached
        else:
            result = await query_threat_intel(ip=alert.target_ip)
            set_cache(cache_key, result)
            enrichment["threat_intel"]["target_ip"] = result

    # Query file hash
    if alert.file_hash:
        cache_key = f"threat_hash:{alert.file_hash}"
        cached = check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["file_hash"] = cached
        else:
            result = await query_threat_intel(file_hash=alert.file_hash)
            set_cache(cache_key, result)
            enrichment["threat_intel"]["file_hash"] = result

    # Query URL
    if alert.url:
        cache_key = f"threat_url:{hashlib.md5(alert.url.encode()).hexdigest()}"
        cached = check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["url"] = cached
        else:
            result = await query_threat_intel(url=alert.url)
            set_cache(cache_key, result)
            enrichment["threat_intel"]["url"] = result

    return enrichment


def check_cache(key: str) -> Optional[Dict[str, Any]]:
    """Check if data exists in cache and is not expired."""
    if key in threat_cache:
        data, expiry = threat_cache[key]
        if datetime.utcnow().timestamp() < expiry:
            return data
    return None


def set_cache(key: str, data: Dict[str, Any]):
    """Store data in cache with expiry."""
    expiry_time = datetime.utcnow().timestamp() + CACHE_TTL_SECONDS
    threat_cache[key] = (data, expiry_time)


# =============================================================================
# FastAPI Application
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, publisher, consumer

    logger.info("Starting Threat Intel Aggregator Service")

    try:
        # Initialize threat intel sources
        init_threat_sources()

        # Initialize database
        db_manager = get_database_manager()
        await db_manager.initialize()
        logger.info("✓ Database connected")

        # Initialize message publisher
        publisher = MessagePublisher(config.rabbitmq_url)
        await publisher.connect()
        logger.info("✓ Message publisher connected")

        # Initialize message consumer
        consumer = MessageConsumer(config.rabbitmq_url, "alert.enriched")
        await consumer.connect()
        logger.info("✓ Message consumer connected")

        logger.info("✓ Threat Intel Aggregator Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        logger.info("Shutting down Threat Intel Aggregator Service")

        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")

        if publisher:
            await publisher.close()
            logger.info("✓ Message publisher closed")

        if db_manager:
            await db_manager.close()
            logger.info("✓ Database connection closed")

        logger.info("✓ Threat Intel Aggregator Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Threat Intel Aggregator API",
    description="Aggregates threat intelligence from multiple sources",
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
    """Consume enriched alerts and add threat intelligence."""

    async def process_message(message: dict):
        try:
            payload = message.get("payload", {})
            message_id = message.get("message_id", "unknown")

            logger.info(f"Processing message {message_id}")

            # Extract alert from payload
            alert_data = payload.get("alert")
            existing_enrichment = payload.get("enrichment", {})

            if not alert_data:
                logger.warning("No alert data in message")
                return

            alert = SecurityAlert(**alert_data)

            # Enrich with threat intel
            threat_enrichment = await enrich_with_threat_intel(alert)

            # Merge with existing enrichment
            existing_enrichment.update(threat_enrichment)

            # Create updated enriched message
            enriched_message = {
                "message_id": str(uuid.uuid4()),
                "message_type": "alert.enriched_with_ti",
                "correlation_id": alert.alert_id,
                "original_message_id": message_id,
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0",
                "payload": {
                    "alert": alert.model_dump(),
                    "enrichment": existing_enrichment,
                },
            }

            # Publish enriched alert (with threat intel)
            await publisher.publish("alert.enriched", enriched_message)

            logger.info(
                "Alert enriched with threat intel",
                extra={
                    "message_id": message_id,
                    "alert_id": alert.alert_id,
                },
            )

        except Exception as e:
            logger.error(f"Threat intel enrichment failed: {e}", exc_info=True)
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
        enabled_sources = [s.name for s in threat_sources if s.enabled]

        return {
            "status": "healthy",
            "service": "threat-intel-aggregator",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "database": "connected" if db_manager else "disconnected",
                "message_queue_consumer": "connected" if consumer else "disconnected",
                "message_queue_publisher": "connected" if publisher else "disconnected",
                "threat_intel_sources": enabled_sources,
                "cache_size": len(threat_cache),
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "service": "threat-intel-aggregator",
            "error": str(e),
        }


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get threat intel metrics."""
    return {
        "cache_size": len(threat_cache),
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "sources_enabled": len([s for s in threat_sources if s.enabled]),
        "service": "threat-intel-aggregator",
    }


@app.post("/api/v1/query", tags=["Query"])
async def manual_query(
    ip: str = None,
    file_hash: str = None,
    url: str = None,
):
    """
    Manually query threat intelligence (for testing).

    Args:
        ip: IP address to query
        file_hash: File hash to query
        url: URL to query

    Returns:
        Threat intelligence results
    """
    try:
        if not any([ip, file_hash, url]):
            return {
                "success": False,
                "error": "Must provide at least one of: ip, file_hash, url",
            }

        result = await query_threat_intel(ip=ip, file_hash=file_hash, url=url)
        return {
            "success": True,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Manual query failed: {e}")
        return {
            "success": False,
            "error": str(e),
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
