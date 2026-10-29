from typing import Literal

from pydantic import BaseModel, Field

DetectorName = Literal["auto", "ensemble", "codebert", "ast", "regex"]
Severity = Literal["high", "medium", "low"]


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=2_000_000)
    filename: str = "snippet.js"
    language: Literal["javascript", "typescript", "tsx"] | None = None
    detector: DetectorName | None = None
    explain: bool = False
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class Explanation(BaseModel):
    summary: str
    why_vulnerable: str
    attack_example: str
    fix_code: str
    false_positive_likelihood: Literal["low", "medium", "high"]
    source: Literal["groq", "offline"]
    model: str | None = None
    note: str | None = None


class Finding(BaseModel):
    id: str
    file: str
    function: str
    function_kind: str
    start_line: int
    end_line: int
    pattern: str
    confidence: float
    vulnerable_probability: float
    severity: Severity
    evidence_lines: list[int]
    detectors: dict[str, float | None]
    message: str
    code: str
    explanation: Explanation | None = None


class FileReport(BaseModel):
    file: str
    language: str
    functions_scanned: int
    findings: list[Finding]
    error: str | None = None


class ScanSummary(BaseModel):
    files_scanned: int
    functions_scanned: int
    total_findings: int
    by_severity: dict[str, int]
    by_pattern: dict[str, int]
    detector: str
    model_available: bool
    llm_mode: Literal["groq", "offline", "disabled"]
    duration_ms: float


class ScanResponse(BaseModel):
    summary: ScanSummary
    files: list[FileReport]


class ExplainRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=200_000)
    pattern: str
    function: str = "<snippet>"
    confidence: float | None = None
    evidence_lines: list[int] = []


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    llm_mode: Literal["groq", "offline"]


class ModelInfo(BaseModel):
    model_loaded: bool
    model_dir: str
    labels: list[str]
    device: str | None
    temperature: float | None
    metrics: dict | None
    load_error: str | None
    detectors: list[str]
    default_detector: str
