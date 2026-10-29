from fastapi import APIRouter, Request

from app.schemas import ExplainRequest, Explanation

router = APIRouter(prefix="/api", tags=["explain"])


@router.post("/explain", response_model=Explanation)
async def explain(body: ExplainRequest, request: Request) -> Explanation:
    explainer = request.app.state.engine.explainer
    return await explainer.explain(body.code, body.pattern, body.function, body.confidence, body.evidence_lines)
