from fastapi import APIRouter, Request

from app.labels import LABELS
from app.schemas import HealthResponse, ModelInfo

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    engine = request.app.state.engine
    return HealthResponse(status="ok", model_loaded=engine.codebert.available, llm_mode=engine.llm_mode)


@router.get("/model-info", response_model=ModelInfo)
async def model_info(request: Request) -> ModelInfo:
    engine = request.app.state.engine
    cb = engine.codebert
    detectors = ["auto", "ast", "regex"] + (["ensemble", "codebert"] if cb.available else [])
    return ModelInfo(
        model_loaded=cb.available,
        model_dir=str(cb.model_dir),
        labels=cb.labels if cb.available else LABELS,
        device=cb.device,
        temperature=cb.temperature if cb.available else None,
        metrics=cb.metrics,
        load_error=cb.load_error,
        detectors=detectors,
        default_detector=engine.resolve_detector("auto"),
    )
