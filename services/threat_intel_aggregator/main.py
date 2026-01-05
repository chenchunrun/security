"""Threat Intel Aggregator Service - Aggregates threat intelligence from multiple sources."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio

from shared.models import (
    ThreatIntelQuery,
    AggregatedThreatIntel,
    IOCType,
    ThreatLevel,
    IntelSource,
)
from shared.messaging import MessagePublisher, MessageConsumer
from shared.utils import get_logger, Config, CacheManager
from shared.database import get_database_manager

logger = get_logger(__name__)
config = Config()

db_manager = None
publisher = None
consumer = None
cache = None


@app.on_event("startup")
async def startup():
    global db_manager, publisher, consumer, cache
    db_manager = get_database_manager()
    await db_manager.initialize()

    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "alert.enriched")
    await consumer.connect()

    cache = CacheManager(config.redis_url)
    await cache.connect()

    asyncio.create_task(consume_alerts())


@app.on_event("shutdown")
async def shutdown():
    await consumer.close()
    await publisher.close()
    await cache.close()
    await db_manager.close()


app = FastAPI(title="Threat Intel Aggregator", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def consume_alerts():
    """Consume enriched alerts and query threat intel."""
    async def process_message(message: dict):
        try:
            payload = message["payload"]
            alert = payload["alert"]

            # Extract IOCs
            iocs = extract_iocs(alert)

            # Query threat intel
            for ioc in iocs:
                intel = await query_threat_intel(ioc)
                if intel:
                    # TODO: Update alert with threat intel
                    logger.info(f"Threat intel found for {ioc['value']}")

        except Exception as e:
            logger.error(f"Threat intel query failed: {e}")

    await consumer.consume(process_message)


def extract_iocs(alert: dict) -> list[dict]:
    """Extract IOCs from alert."""
    iocs = []

    # IP addresses
    if alert.get("source_ip"):
        iocs.append({"type": IOCType.IP_ADDRESS, "value": alert["source_ip"]})
    if alert.get("target_ip"):
        iocs.append({"type": IOCType.IP_ADDRESS, "value": alert["target_ip"]})

    # File hashes
    if alert.get("file_hash"):
        hash_len = len(alert["file_hash"])
        if hash_len == 32:
            iocs.append({"type": IOCType.FILE_HASH_MD5, "value": alert["file_hash"]})
        elif hash_len == 40:
            iocs.append({"type": IOCType.FILE_HASH_SHA1, "value": alert["file_hash"]})
        elif hash_len == 64:
            iocs.append({"type": IOCType.FILE_HASH_SHA256, "value": alert["file_hash"]})

    # URLs
    if alert.get("url"):
        iocs.append({"type": IOCType.URL, "value": alert["url"]})

    return iocs


async def query_threat_intel(ioc: dict) -> AggregatedThreatIntel:
    """Query threat intel from multiple sources."""
    cache_key = f"threat_intel:{ioc['type']}:{ioc['value']}"

    # Check cache
    cached = await cache.get(cache_key)
    if cached:
        return AggregatedThreatIntel(**cached)

    # Query sources
    sources = []
    positive_count = 0

    # TODO: Implement actual API calls to threat intel sources
    # VirusTotal, Abuse.ch, MISP, etc.

    # For now, return mock data
    intel = AggregatedThreatIntel(
        ioc_type=ioc["type"],
        ioc_value=ioc["value"],
        threat_level=ThreatLevel.UNKNOWN,
        threat_score=0.0,
        sources=sources,
        positive_sources=positive_count,
        total_sources=0,
    )

    # Cache for 1 hour
    await cache.set(cache_key, intel.model_dump(), ttl=3600)

    return intel


@app.post("/api/v1/threat-intel/query")
async def query_threat_intel_api(query: ThreatIntelQuery):
    """API endpoint to query threat intel."""
    intel = await query_threat_intel({
        "type": query.ioc_type,
        "value": query.ioc_value,
    })

    return {
        "success": True,
        "data": intel.model_dump(),
        "meta": {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": str(uuid.uuid4()),
        }
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "threat-intel-aggregator"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.host, port=config.port)
