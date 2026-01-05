"""AI Triage Agent Service - Uses LangChain to perform intelligent alert triage."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
import uuid
import asyncio
from typing import Dict, Any, Optional
import httpx

from shared.models import (
    SecurityAlert,
    EnrichedContext,
    AggregatedThreatIntel,
    RiskAssessment,
    TriageResult,
    RiskLevel,
    RemediationPriority,
    ActionType,
    RemediationAction,
    TaskType,
    LLMRequest,
    LLMProvider,
    LLMModel,
)
from shared.messaging import MessagePublisher, MessageConsumer
from shared.utils import get_logger, Config
from shared.database import get_database_manager
from shared.errors import TriageError

logger = get_logger(__name__)
config = Config()

db_manager = None
publisher = None
consumer = None
http_client: httpx.AsyncClient = None

# LLM Router endpoint
LLM_ROUTER_URL = "http://localhost:8001"  # Configure via environment


# System prompts for different alert types
TRIAGE_SYSTEM_PROMPTS = {
    "malware": """You are an expert security analyst specializing in malware analysis.
Your task is to analyze security alerts related to malware infections and provide:
1. Risk assessment (critical, high, medium, low, info)
2. Confidence level in your assessment (0-100)
3. Detailed reasoning for your assessment
4. Recommended remediation actions
5. Priority level (critical, high, medium, low)

Consider the following factors:
- Malware type and capabilities
- Threat intelligence indicators
- Target asset criticality
- Network context
- User context
- Historical patterns

Provide your assessment in a structured format.""",

    "phishing": """You are an expert security analyst specializing in phishing attacks.
Your task is to analyze security alerts related to phishing and provide:
1. Risk assessment (critical, high, medium, low, info)
2. Confidence level in your assessment (0-100)
3. Detailed reasoning for your assessment
4. Recommended remediation actions
5. Priority level (critical, high, medium, low)

Consider the following factors:
- Email characteristics and sender reputation
- URL and domain analysis
- Attachment analysis
- User context
- Threat intelligence
- Historical phishing patterns

Provide your assessment in a structured format.""",

    "intrusion": """You are an expert security analyst specializing in intrusion detection.
Your task is to analyze security alerts related to network intrusions and provide:
1. Risk assessment (critical, high, medium, low, info)
2. Confidence level in your assessment (0-100)
3. Detailed reasoning for your assessment
4. Recommended remediation actions
5. Priority level (critical, high, medium, low)

Consider the following factors:
- Attack patterns and techniques
- Source and destination context
- Threat intelligence
- Network topology
- Asset criticality
- Lateral movement potential

Provide your assessment in a structured format.""",

    "default": """You are an expert security analyst.
Your task is to analyze security alerts and provide:
1. Risk assessment (critical, high, medium, low, info)
2. Confidence level in your assessment (0-100)
3. Detailed reasoning for your assessment
4. Recommended remediation actions
5. Priority level (critical, high, medium, low)

Consider all available context including threat intelligence, network information, and asset details.

Provide your assessment in a structured format."""
}


def build_triage_prompt(
    alert: SecurityAlert,
    context: Optional[EnrichedContext] = None,
    threat_intel: Optional[AggregatedThreatIntel] = None,
) -> str:
    """Build triage prompt from alert context."""
    prompt_parts = [
        f"# Alert Information",
        f"Alert ID: {alert.alert_id}",
        f"Type: {alert.alert_type}",
        f"Severity: {alert.severity}",
        f"Description: {alert.description}",
        f"Timestamp: {alert.timestamp}",
    ]

    # Add network context
    if context:
        prompt_parts.append("\n# Network Context")
        if context.source_network:
            prompt_parts.append(
                f"Source IP: {context.source_network.ip_address}\n"
                f"Internal: {context.source_network.is_internal}\n"
                f"Reputation Score: {context.source_network.reputation_score}"
            )
        if context.target_network:
            prompt_parts.append(
                f"Target IP: {context.target_network.ip_address}\n"
                f"Internal: {context.target_network.is_internal}"
            )

        # Add asset context
        if context.asset:
            prompt_parts.append(
                f"\n# Asset Context\n"
                f"Asset ID: {context.asset.asset_id}\n"
                f"Asset Name: {context.asset.asset_name}\n"
                f"Asset Type: {context.asset.asset_type}\n"
                f"Criticality: {context.asset.criticality}"
            )

        # Add user context
        if context.user:
            prompt_parts.append(
                f"\n# User Context\n"
                f"User ID: {context.user.user_id}\n"
                f"Username: {context.user.username}\n"
                f"Department: {context.user.department}"
            )

    # Add threat intelligence
    if threat_intel:
        prompt_parts.append(
            f"\n# Threat Intelligence\n"
            f"IOC Type: {threat_intel.ioc_type}\n"
            f"IOC Value: {threat_intel.ioc_value}\n"
            f"Threat Level: {threat_intel.threat_level}\n"
            f"Threat Score: {threat_intel.threat_score}\n"
            f"Sources: {len(threat_intel.sources)}\n"
            f"Positive Detections: {threat_intel.positive_sources}/{threat_intel.total_sources}"
        )

    prompt_parts.append(
        "\n# Instructions\n"
        "Based on the above information, provide a comprehensive risk assessment "
        "including your reasoning, confidence level, and recommended actions."
    )

    return "\n".join(prompt_parts)


def parse_triage_response(llm_response: str) -> Dict[str, Any]:
    """
    Parse LLM response into structured triage result.

    Expected format (though LLM may vary):
    - Risk Level: [critical/high/medium/low/info]
    - Confidence: [0-100]
    - Reasoning: [detailed explanation]
    - Recommended Actions: [list of actions]
    - Priority: [critical/high/medium/low]
    """
    import re

    result = {
        "risk_level": RiskLevel.MEDIUM,
        "confidence": 50.0,
        "reasoning": llm_response,
        "recommended_actions": [],
        "priority": RemediationPriority.MEDIUM,
    }

    # Try to extract structured information
    # Risk level
    risk_match = re.search(
        r"(?i)(risk\s*level|severity)\s*:\s*(critical|high|medium|low|info)",
        llm_response
    )
    if risk_match:
        risk_str = risk_match.group(2).lower()
        risk_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "info": RiskLevel.INFO,
        }
        result["risk_level"] = risk_map.get(risk_str, RiskLevel.MEDIUM)

    # Confidence
    conf_match = re.search(r"(?i)confidence\s*:\s*(\d+)", llm_response)
    if conf_match:
        result["confidence"] = float(conf_match.group(1))

    # Priority
    prio_match = re.search(
        r"(?i)priority\s*:\s*(critical|high|medium|low)",
        llm_response
    )
    if prio_match:
        prio_str = prio_match.group(2).lower()
        prio_map = {
            "critical": RemediationPriority.CRITICAL,
            "high": RemediationPriority.HIGH,
            "medium": RemediationPriority.MEDIUM,
            "low": RemediationPriority.LOW,
        }
        result["priority"] = prio_map.get(prio_str, RemediationPriority.MEDIUM)

    return result


async def call_llm_router(
    prompt: str,
    task_type: TaskType,
    alert_type: str,
) -> str:
    """Call LLM Router for analysis."""
    # Get appropriate system prompt
    system_prompt = TRIAGE_SYSTEM_PROMPTS.get(
        alert_type.lower(),
        TRIAGE_SYSTEM_PROMPTS["default"]
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    request = LLMRequest(
        task_type=task_type,
        messages=messages,
        temperature=0.3,  # Lower temperature for more consistent analysis
        max_tokens=3000,
    )

    try:
        # Call LLM Router service
        async with http_client.AsyncClient() as client:
            response = await client.post(
                f"{LLM_ROUTER_URL}/api/v1/chat/completions",
                json=request.model_dump(),
                timeout=60.0
            )
            response.raise_for_status()
            data = response.json()

            # Extract generated text
            if data["data"]["choices"]:
                return data["data"]["choices"][0]["message"]["content"]
            else:
                raise TriageError("Empty response from LLM Router")

    except httpx.HTTPError as e:
        logger.error(f"LLM Router call failed: {e}")
        raise TriageError(f"LLM Router call failed: {str(e)}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, publisher, consumer, http_client

    logger.info("Starting AI Triage Agent service...")

    # Initialize database
    db_manager = get_database_manager()
    await db_manager.initialize()

    # Initialize messaging
    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "alert.enriched")
    await consumer.connect()

    # Initialize HTTP client
    http_client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    # Start consuming alerts
    asyncio.create_task(consume_alerts())

    logger.info("AI Triage Agent service started successfully")

    yield

    # Cleanup
    await consumer.close()
    await publisher.close()
    await http_client.aclose()
    await db_manager.close()
    logger.info("AI Triage Agent service stopped")


app = FastAPI(
    title="AI Triage Agent Service",
    description="Uses LangChain to perform intelligent alert triage",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def consume_alerts():
    """Consume enriched alerts and perform AI triage."""
    async def process_message(message: dict):
        try:
            payload = message["payload"]
            alert_data = payload.get("alert")
            context_data = payload.get("context")
            threat_intel_data = payload.get("threat_intel")

            # Parse models
            alert = SecurityAlert(**alert_data)
            context = EnrichedContext(**context_data) if context_data else None
            threat_intel = (
                AggregatedThreatIntel(**threat_intel_data)
                if threat_intel_data
                else None
            )

            logger.info(f"Processing alert {alert.alert_id} for triage")

            # Build triage prompt
            prompt = build_triage_prompt(alert, context, threat_intel)

            # Call LLM for analysis
            llm_response = await call_llm_router(
                prompt,
                TaskType.TRIAGE,
                alert.alert_type.value
            )

            # Parse response
            parsed_result = parse_triage_response(llm_response)

            # Create triage result
            triage_result = TriageResult(
                alert_id=alert.alert_id,
                risk_level=parsed_result["risk_level"],
                confidence=parsed_result["confidence"],
                reasoning=parsed_result["reasoning"][:1000],  # Limit length
                recommended_actions=[
                    RemediationAction(
                        action_type=ActionType.CONTAINMENT,
                        description="Review and isolate affected system",
                        priority=parsed_result["priority"],
                    )
                ],
                triaged_by="ai-agent",
                triaged_at=datetime.utcnow(),
            )

            # Publish result
            await publisher.publish(
                "alert.result",
                {
                    "message_id": str(uuid.uuid4()),
                    "message_type": "alert.triage_result",
                    "payload": {
                        "alert_id": alert.alert_id,
                        "triage_result": triage_result.model_dump(),
                        "llm_raw_response": llm_response,
                    },
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            logger.info(
                f"Alert {alert.alert_id} triage complete: "
                f"risk={triage_result.risk_level.value}, "
                f"confidence={triage_result.confidence}%"
            )

        except Exception as e:
            logger.error(f"Triage failed: {e}", exc_info=True)

    await consumer.consume(process_message)


@app.post("/api/v1/triage", response_model=Dict[str, Any])
async def manual_triage(
    alert: SecurityAlert,
    context: Optional[EnrichedContext] = None,
    threat_intel: Optional[AggregatedThreatIntel] = None,
):
    """
    Manual triage endpoint for on-demand analysis.

    Useful for:
    - Testing triage logic
    - Re-triaging existing alerts
    - Interactive analysis
    """
    try:
        # Build triage prompt
        prompt = build_triage_prompt(alert, context, threat_intel)

        # Call LLM for analysis
        llm_response = await call_llm_router(
            prompt,
            TaskType.TRIAGE,
            alert.alert_type.value
        )

        # Parse response
        parsed_result = parse_triage_response(llm_response)

        # Create triage result
        triage_result = TriageResult(
            alert_id=alert.alert_id,
            risk_level=parsed_result["risk_level"],
            confidence=parsed_result["confidence"],
            reasoning=parsed_result["reasoning"][:1000],
            recommended_actions=[
                RemediationAction(
                    action_type=ActionType.CONTAINMENT,
                    description="Review and isolate affected system",
                    priority=parsed_result["priority"],
                )
            ],
            triaged_by="ai-agent",
            triaged_at=datetime.utcnow(),
        )

        return {
            "success": True,
            "data": {
                "triage_result": triage_result.model_dump(),
                "llm_response": llm_response,
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4()),
            },
        }

    except Exception as e:
        logger.error(f"Manual triage failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4()),
            },
        }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ai-triage-agent",
        "timestamp": datetime.utcnow().isoformat(),
        "llm_router": LLM_ROUTER_URL,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
