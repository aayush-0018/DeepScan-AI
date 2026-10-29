from __future__ import annotations

import asyncio
import time

from app.config import Settings
from app.detectors.ast_detector import AstRuleDetector
from app.detectors.base import Hit
from app.detectors.codebert_detector import CodeBertDetector
from app.detectors.ensemble import EnsembleDetector
from app.detectors.regex_detector import RegexDetector
from app.extraction.functions import parse_source
from app.llm.groq_explainer import get_explainer
from app.report import hit_to_finding, summarize
from app.schemas import FileReport, ScanResponse


class ScanEngine:
    def __init__(self, settings: Settings, load_model: bool = True):
        self.settings = settings
        self.codebert = CodeBertDetector(settings.resolved_model_dir, device=settings.device)
        if load_model:
            self.codebert.load()
        self.ast = AstRuleDetector()
        self.regex = RegexDetector()
        self.ensemble = EnsembleDetector(self.codebert, self.ast)
        self.explainer = get_explainer(settings)

    @property
    def llm_mode(self) -> str:
        return self.explainer.mode

    def resolve_detector(self, requested: str | None) -> str:
        name = requested or self.settings.default_detector
        if name == "auto":
            return "ensemble" if self.codebert.available else "ast"
        if name in ("codebert", "ensemble") and not self.codebert.available:
            raise ModelUnavailableError(self.codebert.load_error or "CodeBERT model is not loaded.")
        return name

    def _detector(self, name: str):
        return {"ensemble": self.ensemble, "codebert": self.codebert, "ast": self.ast, "regex": self.regex}[name]

    def scan_file(self, code: str, filename: str, language: str | None, detector: str, threshold: float) -> FileReport:
        try:
            parsed = parse_source(code, filename, language)
        except Exception as exc:  # noqa: BLE001
            return FileReport(file=filename, language=language or "unknown", functions_scanned=0, findings=[],
                              error=f"Parse failed: {exc}")
        units = parsed.units[: self.settings.max_functions_per_request]
        parsed.units = units
        hits: list[Hit] = self._detector(detector).detect(parsed)
        hits = [h for h in hits if h.confidence >= threshold]
        hits.sort(key=lambda h: (-h.confidence, h.unit.start_line))
        findings = [hit_to_finding(h, "") for h in hits]
        error = "Source has syntax errors; results may be incomplete." if parsed.has_errors else None
        scanned = sum(1 for u in units if u.kind != "module") or len(units)
        return FileReport(file=filename, language=parsed.language, functions_scanned=scanned, findings=findings,
                          error=error)

    async def scan(
        self,
        sources: list[tuple[str, str]],
        language: str | None = None,
        detector: str | None = None,
        threshold: float | None = None,
        explain: bool = False,
    ) -> ScanResponse:
        started = time.perf_counter()
        name = self.resolve_detector(detector)
        thr = self.settings.confidence_threshold if threshold is None else threshold

        reports = await asyncio.to_thread(
            lambda: [self.scan_file(code, fname, language, name, thr) for fname, code in sources]
        )
        counter = 0
        for report in reports:
            for finding in report.findings:
                counter += 1
                finding.id = f"f_{counter}"

        if explain:
            findings = [f for r in reports for f in r.findings]
            explanations = await asyncio.gather(
                *(
                    self.explainer.explain(f.code, f.pattern, f.function, f.confidence, f.evidence_lines)
                    for f in findings
                )
            )
            for finding, explanation in zip(findings, explanations, strict=True):
                finding.explanation = explanation

        duration = (time.perf_counter() - started) * 1000
        summary = summarize(
            reports,
            detector=name,
            model_available=self.codebert.available,
            llm_mode=self.llm_mode if explain else "disabled",
            duration_ms=duration,
        )
        return ScanResponse(summary=summary, files=reports)


class ModelUnavailableError(RuntimeError):
    pass
