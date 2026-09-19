"""FastAPI shell over `SocService`. No SOC logic lives here.

Run (from the repo root):
    app/.venv/Scripts/python.exe -m app.api

Binds to 127.0.0.1 only. This is a local, unauthenticated lab console and
must not be exposed on a network interface.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..soc_core.efficiency import SCALES, Pricing
from .service import (
    MAX_REASON_LENGTH,
    ConflictError,
    NotFoundError,
    ProviderUnavailableError,
    SocService,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("soc.api")

INCIDENT_ID = Path(pattern=r"^inc-\d{4}$", description="e.g. inc-0001")
SCENARIO_ID = Path(pattern=r"^[a-z0-9-]{1,40}$", description="from GET /api/scenarios")

# The console is served by Vite on these origins. No wildcard.
ALLOWED_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


class DecisionRequest(BaseModel):
    """An analyst decision. The client can only reference a server-generated
    action_id. It cannot name an action, a target or an approver:
    `extra="forbid"` rejects any attempt to send them."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(pattern=r"^act-\d{2,3}$")
    decision: Literal["approve", "reject"]
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)


class BenchmarkRequest(BaseModel):
    """Which synthetic scales to measure. Only values from SCALES are accepted."""

    model_config = ConfigDict(extra="forbid")

    scales: list[int] = Field(min_length=1, max_length=len(SCALES))
    force: bool = False


class CostRequest(BaseModel):
    """User-supplied pricing. Nothing here is a vendor price; the client
    decides the rates and the model label."""

    model_config = ConfigDict(extra="forbid")

    scale: int
    model: str = Field(default="example-model", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 ._:/()-]+$")
    input_per_mtok: float = Field(ge=0, le=10_000)
    output_per_mtok: float = Field(ge=0, le=10_000)
    investigations: int = Field(default=1, ge=0, le=100_000_000)
    output_tokens: int = Field(default=2500, ge=0, le=1_000_000)
    context_window: int | None = Field(default=None, ge=1_000, le=100_000_000)


def create_app(service: SocService | None = None) -> FastAPI:
    """App factory so tests can inject a fresh or failure-simulating service."""
    soc = service or SocService()
    app = FastAPI(
        title="AI SOC Command Center API",
        version="0.1.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    # -- error mapping: SOC-style messages, never stack traces ---------------

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"error": str(exc)})

    @app.exception_handler(ConflictError)
    async def _conflict(_: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error": str(exc)})

    @app.exception_handler(ProviderUnavailableError)
    async def _unavailable(_: Request, exc: ProviderUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"error": str(exc)})

    @app.exception_handler(ValueError)
    async def _bad_value(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted({".".join(str(p) for p in err.get("loc", [])[1:]) for err in exc.errors()})
        return JSONResponse(
            status_code=422,
            content={"error": "Invalid request.", "fields": [f for f in fields if f]},
        )

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled API error")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal error in the SOC API. No state was changed."},
        )

    # -- read endpoints ------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return soc.health()

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        return soc.metrics()

    @app.get("/api/incidents")
    def incidents() -> list[dict[str, Any]]:
        return soc.list_incidents()

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str = INCIDENT_ID) -> dict[str, Any]:
        return soc.incident_detail(incident_id)

    @app.get("/api/incidents/{incident_id}/context")
    def incident_context(incident_id: str = INCIDENT_ID) -> dict[str, Any]:
        """The exact redacted evidence context an LLM would receive."""
        return soc.context_pack(incident_id)

    @app.get("/api/alerts")
    def alerts() -> list[dict[str, Any]]:
        return soc.list_alerts()

    @app.get("/api/events")
    def events(limit: int = Query(default=500, ge=1, le=1000)) -> list[dict[str, Any]]:
        return soc.list_events(limit)

    @app.get("/api/screening")
    def screening() -> list[dict[str, Any]]:
        return soc.screening()

    @app.get("/api/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return soc.list_scenarios()

    # -- AI efficiency lab (local benchmark; never calls a model) -------------

    @app.get("/api/efficiency/benchmark")
    def efficiency_status() -> dict[str, Any]:
        return soc.efficiency_status()

    @app.post("/api/efficiency/benchmark")
    def efficiency_run(body: BenchmarkRequest) -> dict[str, Any]:
        return soc.efficiency_run(body.scales, body.force)

    @app.get("/api/efficiency/fidelity")
    def efficiency_fidelity() -> dict[str, Any]:
        return soc.efficiency_fidelity()

    @app.post("/api/efficiency/cost")
    def efficiency_cost(body: CostRequest) -> dict[str, Any]:
        pricing = Pricing(model=body.model, input_per_mtok=body.input_per_mtok,
                          output_per_mtok=body.output_per_mtok)
        return soc.efficiency_cost(body.scale, pricing, body.investigations,
                                   body.output_tokens, body.context_window)

    @app.get("/api/efficiency/live")
    def efficiency_live() -> dict[str, Any]:
        return soc.efficiency_live()

    # -- correlation engine (debug inspection only) ------------------------------

    @app.get("/api/correlation/debug")
    def correlation_debug(limit: int = Query(default=25, ge=1, le=200)) -> dict[str, Any]:
        return soc.correlation_debug(limit)

    # -- actions -------------------------------------------------------------

    @app.post("/api/scenarios/{scenario_id}/run")
    def run_scenario(scenario_id: str = SCENARIO_ID) -> dict[str, Any]:
        return soc.run_scenario(scenario_id)

    @app.post("/api/incidents/{incident_id}/analyze")
    def analyze(incident_id: str = INCIDENT_ID) -> dict[str, Any]:
        return soc.analyze(incident_id)

    @app.post("/api/incidents/{incident_id}/response-plan")
    def response_plan(incident_id: str = INCIDENT_ID) -> dict[str, Any]:
        return soc.response_plan(incident_id)

    @app.post("/api/incidents/{incident_id}/approve-response")
    def approve_response(body: DecisionRequest, incident_id: str = INCIDENT_ID) -> dict[str, Any]:
        return soc.decide(incident_id, body.action_id, body.decision, body.reason)

    return app


app = create_app()
