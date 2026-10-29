from __future__ import annotations

from collections import Counter

from app.detectors.base import Hit
from app.schemas import FileReport, Finding, ScanSummary

MAX_CODE_CHARS = 8000


def severity(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.65:
        return "medium"
    return "low"


def hit_to_finding(hit: Hit, finding_id: str) -> Finding:
    detectors: dict[str, float | None] = {hit.detector: hit.confidence}
    if hit.probabilities and "_ast" in hit.probabilities:
        detectors["ast"] = hit.probabilities["_ast"] or None
        detectors["codebert"] = round(1 - hit.probabilities.get("SAFE", 1.0), 4) if "SAFE" in hit.probabilities else None
    code = hit.unit.code
    if len(code) > MAX_CODE_CHARS:
        code = code[:MAX_CODE_CHARS] + "\n/* … truncated … */"
    return Finding(
        id=finding_id,
        file=hit.unit.file,
        function=hit.unit.name,
        function_kind=hit.unit.kind,
        start_line=hit.unit.start_line,
        end_line=hit.unit.end_line,
        pattern=hit.pattern,
        confidence=round(hit.confidence, 4),
        vulnerable_probability=round(hit.vulnerable_probability, 4),
        severity=severity(hit.confidence),
        evidence_lines=hit.evidence_lines,
        detectors=detectors,
        message=hit.message,
        code=code,
    )


def summarize(
    files: list[FileReport],
    detector: str,
    model_available: bool,
    llm_mode: str,
    duration_ms: float,
) -> ScanSummary:
    findings = [f for fr in files for f in fr.findings]
    by_severity = Counter(f.severity for f in findings)
    return ScanSummary(
        files_scanned=len(files),
        functions_scanned=sum(fr.functions_scanned for fr in files),
        total_findings=len(findings),
        by_severity={s: by_severity.get(s, 0) for s in ("high", "medium", "low")},
        by_pattern=dict(Counter(f.pattern for f in findings)),
        detector=detector,
        model_available=model_available,
        llm_mode=llm_mode,
        duration_ms=round(duration_ms, 1),
    )
