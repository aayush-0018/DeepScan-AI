from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.extraction.functions import FunctionUnit, ParsedFile


@dataclass
class Hit:
    """A single detector result attributed to one function unit."""

    unit: FunctionUnit
    pattern: str  # a label from app.labels.LABELS (never SAFE for rule detectors)
    confidence: float  # probability of `pattern`
    vulnerable_probability: float  # 1 - P(SAFE)
    detector: str
    message: str
    evidence_lines: list[int] = field(default_factory=list)
    probabilities: dict[str, float] | None = None


class Detector(Protocol):
    name: str

    @property
    def available(self) -> bool: ...

    def detect(self, parsed: ParsedFile) -> list[Hit]:
        """Return hits for vulnerable units only."""
        ...


def innermost_unit(units: list[FunctionUnit], line: int) -> FunctionUnit | None:
    """The smallest unit whose line range contains `line` (module unit as last resort)."""
    best: FunctionUnit | None = None
    for unit in units:
        if unit.start_line <= line <= unit.end_line:
            if best is None or unit.line_count < best.line_count or (
                unit.line_count == best.line_count and unit.depth > best.depth
            ):
                best = unit
    return best


def merge_hits_per_unit(hits: list[Hit]) -> list[Hit]:
    """Collapse multiple hits on the same unit into the strongest one, unioning evidence."""
    by_unit: dict[tuple[int, int, str], list[Hit]] = {}
    for hit in hits:
        key = (hit.unit.start_line, hit.unit.end_line, hit.unit.name)
        by_unit.setdefault(key, []).append(hit)

    merged: list[Hit] = []
    for group in by_unit.values():
        group.sort(key=lambda h: h.confidence, reverse=True)
        top = group[0]
        evidence = sorted({ln for h in group for ln in h.evidence_lines})
        others = sorted({h.pattern for h in group[1:] if h.pattern != top.pattern})
        message = top.message
        if others:
            message += f" Also matches: {', '.join(others)}."
        merged.append(
            Hit(
                unit=top.unit,
                pattern=top.pattern,
                confidence=top.confidence,
                vulnerable_probability=max(h.vulnerable_probability for h in group),
                detector=top.detector,
                message=message,
                evidence_lines=evidence,
                probabilities=top.probabilities,
            )
        )
    return merged
