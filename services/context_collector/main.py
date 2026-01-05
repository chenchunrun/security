"""Context Collector Service - Enriches alerts with context information."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio

from shared.models import SecurityAlert, EnrichedContext, NetworkContext, AssetContext
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

    consumer = MessageConsumer(config.rabbitmq_url, "alert.normalized")
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


app = FastAPI(title="Context Collector", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def consume_alerts():
    """Consume normalized alerts and enrich with context."""
    async def process_message(message: dict):
        try:
            alert = SecurityAlert(**message["payload"])

            # Collect context
            context = await collect_context(alert)

            # Publish enriched alert
            await publisher.publish("alert.enriched", {
                "message_id": str(uuid.uuid4()),
                "message_type": "alert.enriched",
                "payload": {
                    "alert": alert.model_dump(),
                    "context": context.model_dump(),
                },
                "timestamp": datetime.utcnow().isoformat(),
            })

            logger.info(f"Enriched alert {alert.alert_id}")

        except Exception as e:
            logger.error(f"Context collection failed: {e}")

    await consumer.consume(process_message)


async def collect_context(alert: SecurityAlert) -> EnrichedContext:
    """Collect network, asset, and user context."""
    context = EnrichedContext(alert_id=alert.alert_id)

    # Collect network context
    if alert.source_ip:
        context.source_network = await get_network_context(alert.source_ip)
    if alert.target_ip:
        context.target_network = await get_network_context(alert.target_ip)

    # Collect asset context
    if alert.asset_id:
        context.asset = await get_asset_context(alert.asset_id)

    # Collect user context
    if alert.user_id:
        context.user = await get_user_context(alert.user_id)

    context.enrichment_sources = ["network", "asset", "user"]

    return context


async def get_network_context(ip: str) -> NetworkContext:
    """Get network context for IP."""
    # Check cache first
    cache_key = f"network:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return NetworkContext(**cached)

    # TODO: Implement actual network context collection
    # (GeoIP, WHOIS, reputation, etc.)
    context = NetworkContext(
        ip_address=ip,
        is_internal=ip.startswith(("10.", "192.168.", "172.16.")),
        reputation_score=50.0,
    )

    # Cache for 1 hour
    await cache.set(cache_key, context.model_dump(), ttl=3600)

    return context


async def get_asset_context(asset_id: str) -> AssetContext:
    """Get asset context."""
    # TODO: Implement actual CMDB lookup
    return AssetContext(
        asset_id=asset_id,
        asset_name=f"ASSET-{asset_id}",
        asset_type="unknown",
        criticality="medium",
    )


async def get_user_context(user_id: str):
    """Get user context."""
    # TODO: Implement actual directory lookup
    return None


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "context-collector"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.host, port=config.port)
