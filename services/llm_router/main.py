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

"""LLM Router Service - Intelligently routes requests to DeepSeek or Qwen models."""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
import uuid
import time
import asyncio
from typing import Any, Optional, Dict
import httpx

from shared.models import (
    LLMRequest,
    LLMResponse,
    LLMProvider,
    LLMModel,
    TaskType,
    RouterDecision,
    ModelCapabilities,
    SuccessResponse,
    ResponseMeta,
    LLMChoice,
    LLMUsage,
    LLMMessage,
)
from shared.utils import get_logger, Config
from shared.database import get_database_manager

logger = get_logger(__name__)
config = Config()

db_manager = None
http_client: httpx.AsyncClient = None

# Model capabilities registry
MODEL_CAPABILITIES: Dict[LLMModel, ModelCapabilities] = {
    # DeepSeek models
    LLMModel.DEEPSEEK_V3: ModelCapabilities(
        model=LLMModel.DEEPSEEK_V3,
        max_context=32000,
        supports_streaming=True,
        cost_per_1k_tokens=0.002,
        speed=8,
        reasoning_quality=9,
        best_for=[TaskType.TRIAGE, TaskType.ANALYSIS, TaskType.CODE_REVIEW],
    ),
    LLMModel.DEEPSEEK_CODER: ModelCapabilities(
        model=LLMModel.DEEPSEEK_CODER,
        max_context=16000,
        supports_streaming=True,
        cost_per_1k_tokens=0.001,
        speed=9,
        reasoning_quality=7,
        best_for=[TaskType.CODE_REVIEW, TaskType.CLASSIFICATION],
    ),
    # Qwen models
    LLMModel.QWEN3_MAX: ModelCapabilities(
        model=LLMModel.QWEN3_MAX,
        max_context=32000,
        supports_streaming=True,
        cost_per_1k_tokens=0.004,
        speed=7,
        reasoning_quality=10,
        best_for=[TaskType.ANALYSIS, TaskType.TRIAGE, TaskType.GENERAL],
    ),
    LLMModel.QWEN3_PLUS: ModelCapabilities(
        model=LLMModel.QWEN3_PLUS,
        max_context=32000,
        supports_streaming=True,
        cost_per_1k_tokens=0.002,
        speed=8,
        reasoning_quality=8,
        best_for=[TaskType.TRIAGE, TaskType.ANALYSIS, TaskType.SUMMARIZATION],
    ),
    LLMModel.QWEN3_TURBO: ModelCapabilities(
        model=LLMModel.QWEN3_TURBO,
        max_context=8000,
        supports_streaming=True,
        cost_per_1k_tokens=0.0005,
        speed=10,
        reasoning_quality=6,
        best_for=[TaskType.CLASSIFICATION, TaskType.SUMMARIZATION, TaskType.GENERAL],
    ),
}

# Provider API endpoints (configure via environment)
PROVIDER_ENDPOINTS = {
    LLMProvider.DEEPSEEK: "https://api.deepseek.com/v1",
    LLMProvider.QWEN: "https://dashscope.aliyuncs.com/compatible-mode/v1",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, http_client

    logger.info("Starting LLM Router service...")

    # Initialize database
    db_manager = get_database_manager()
    await db_manager.initialize()

    # Initialize HTTP client for LLM API calls
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(60.0, connect=10.0),
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=100)
    )

    logger.info("LLM Router service started successfully")

    yield

    # Cleanup
    await http_client.aclose()
    await db_manager.close()
    logger.info("LLM Router service stopped")


app = FastAPI(
    title="LLM Router Service",
    description="Intelligently routes LLM requests to optimal models",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def route_request(request: LLMRequest) -> RouterDecision:
    """
    Route request to optimal model based on task and context.

    Routing strategy:
    1. If model specified, use it
    2. Match task type to model capabilities
    3. Consider cost vs quality tradeoff
    4. Check request complexity (token count)
    5. Apply fallback logic if needed
    """
    # If user specified a model, use it
    if request.model:
        caps = MODEL_CAPABILITIES.get(request.model)
        if not caps:
            raise HTTPException(
                status_code=400,
                detail=f"Model {request.model} not found"
            )

        provider = (
            LLMProvider.DEEPSEEK
            if "deepseek" in request.model.value
            else LLMProvider.QWEN
        )

        return RouterDecision(
            selected_provider=provider,
            selected_model=request.model,
            reason="User specified model",
            confidence=1.0,
            alternatives=[],
        )

    # Calculate request complexity
    total_tokens = sum(len(msg.get("content", "")) // 4 for msg in request.messages)

    # Select based on task type
    selected_model: Optional[LLMModel] = None
    reason = ""
    confidence = 0.8

    # Priority: match task type to best models
    for model, caps in MODEL_CAPABILITIES.items():
        if request.task_type in caps.best_for:
            # Consider complexity
            if total_tokens > caps.max_context:
                continue  # Skip if context too large

            # Select best match
            if not selected_model or caps.reasoning_quality > MODEL_CAPABILITIES[
                selected_model
            ].reasoning_quality:
                selected_model = model
                reason = f"Best match for {request.task_type} task"
                confidence = 0.9

    # Fallback to default if no match
    if not selected_model:
        selected_model = LLMModel.QWEN3_TURBO
        reason = "Default model for general tasks"
        confidence = 0.7

    # Determine provider from model
    provider = (
        LLMProvider.DEEPSEEK
        if "deepseek" in selected_model.value
        else LLMProvider.QWEN
    )

    # Get alternatives
    alternatives = [
        m
        for m in MODEL_CAPABILITIES.keys()
        if m != selected_model
        and request.task_type in MODEL_CAPABILITIES[m].best_for
    ][:3]

    return RouterDecision(
        selected_provider=provider,
        selected_model=selected_model,
        reason=reason,
        confidence=confidence,
        fallback_used=False,
        alternatives=alternatives,
    )


async def call_deepseek(
    request: LLMRequest,
    decision: RouterDecision,
    api_key: str,
) -> LLMResponse:
    """Call DeepSeek API."""
    endpoint = f"{PROVIDER_ENDPOINTS[LLMProvider.DEEPSEEK]}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": decision.selected_model.value,
        "messages": request.messages,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
        "top_p": request.top_p,
        "stream": request.stream,
    }

    try:
        response = await http_client.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()

        # Convert to our standard format
        return LLMResponse(
            id=data.get("id", f"deepseek-{uuid.uuid4()}"),
            object=data.get("object", "chat.completion"),
            created=data.get("created", int(time.time())),
            model=decision.selected_model,
            provider=LLMProvider.DEEPSEEK,
            choices=[
                LLMChoice(
                    index=c["index"],
                    message=LLMMessage(
                        role=c["message"]["role"],
                        content=c["message"]["content"],
                    ),
                    finish_reason=c.get("finish_reason"),
                )
                for c in data.get("choices", [])
            ],
            usage=LLMUsage(
                prompt_tokens=data["usage"]["prompt_tokens"],
                completion_tokens=data["usage"]["completion_tokens"],
                total_tokens=data["usage"]["total_tokens"],
            ),
            routing_decision=decision.model_dump(),
        )

    except httpx.HTTPError as e:
        logger.error(f"DeepSeek API error: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"DeepSeek API error: {str(e)}"
        )


async def call_qwen(
    request: LLMRequest,
    decision: RouterDecision,
    api_key: str,
) -> LLMResponse:
    """Call Qwen API."""
    endpoint = f"{PROVIDER_ENDPOINTS[LLMProvider.QWEN]}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": decision.selected_model.value,
        "messages": request.messages,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
        "top_p": request.top_p,
        "stream": request.stream,
    }

    try:
        response = await http_client.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()

        # Convert to our standard format
        return LLMResponse(
            id=data.get("id", f"qwen-{uuid.uuid4()}"),
            object=data.get("object", "chat.completion"),
            created=data.get("created", int(time.time())),
            model=decision.selected_model,
            provider=LLMProvider.QWEN,
            choices=[
                LLMChoice(
                    index=c["index"],
                    message=LLMMessage(
                        role=c["message"]["role"],
                        content=c["message"]["content"],
                    ),
                    finish_reason=c.get("finish_reason"),
                )
                for c in data.get("choices", [])
            ],
            usage=LLMUsage(
                prompt_tokens=data["usage"]["prompt_tokens"],
                completion_tokens=data["usage"]["completion_tokens"],
                total_tokens=data["usage"]["total_tokens"],
            ),
            routing_decision=decision.model_dump(),
        )

    except httpx.HTTPError as e:
        logger.error(f"Qwen API error: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Qwen API error: {str(e)}"
        )


@app.post("/api/v1/chat/completions", response_model=SuccessResponse[LLMResponse])
async def chat_completions(request: LLMRequest):
    """
    Main endpoint for LLM chat completions.

    Automatically routes to the best model based on:
    - Task type
    - Request complexity
    - Model capabilities
    - Cost vs quality tradeoffs
    """
    try:
        # Route request
        decision = route_request(request)
        logger.info(
            f"Routing request to {decision.selected_model.value} "
            f"(reason: {decision.reason})"
        )

        # Get API key from environment
        if decision.selected_provider == LLMProvider.DEEPSEEK:
            api_key = config.get("DEEPSEEK_API_KEY")
            if not api_key:
                raise HTTPException(
                    status_code=500,
                    detail="DEEPSEEK_API_KEY not configured"
                )

            response = await call_deepseek(request, decision, api_key)

        else:  # QWEN
            api_key = config.get("QWEN_API_KEY")
            if not api_key:
                raise HTTPException(
                    status_code=500,
                    detail="QWEN_API_KEY not configured"
                )

            response = await call_qwen(request, decision, api_key)

        logger.info(
            f"Request completed using {response.provider.value}/{response.model.value} "
            f"(tokens: {response.usage.total_tokens})"
        )

        return SuccessResponse(
            data=response,
            meta=ResponseMeta(
                timestamp=datetime.utcnow(),
                request_id=str(uuid.uuid4()),
                version="1.0.0",
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat completion failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/models", response_model=SuccessResponse[Dict[str, ModelCapabilities]])
async def list_models():
    """List available models and their capabilities."""
    return SuccessResponse(
        data=MODEL_CAPABILITIES,
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.get("/api/v1/capabilities/{model}", response_model=SuccessResponse[ModelCapabilities])
async def get_model_capabilities(model: LLMModel):
    """Get capabilities for a specific model."""
    caps = MODEL_CAPABILITIES.get(model)
    if not caps:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model} not found"
        )

    return SuccessResponse(
        data=caps,
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.post("/api/v1/route", response_model=SuccessResponse[RouterDecision])
async def route_test(request: LLMRequest):
    """
    Test routing decision without making an actual LLM call.

    Useful for understanding how requests will be routed.
    """
    decision = route_request(request)

    return SuccessResponse(
        data=decision,
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.get("/health", response_model=Dict[str, Any])
async def health_check():
    """Health check endpoint."""
    health_status = {
        "status": "healthy",
        "service": "llm-router",
        "timestamp": datetime.utcnow().isoformat(),
        "models": {
            "total": len(MODEL_CAPABILITIES),
            "deepseek": len([m for m in MODEL_CAPABILITIES.keys() if "deepseek" in m.value]),
            "qwen": len([m for m in MODEL_CAPABILITIES.keys() if "qwen" in m.value]),
        },
    }

    # Check API keys
    deepseek_key = config.get("DEEPSEEK_API_KEY")
    qwen_key = config.get("QWEN_API_KEY")

    health_status["api_keys"] = {
        "deepseek": "configured" if deepseek_key else "missing",
        "qwen": "configured" if qwen_key else "missing",
    }

    return health_status


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
