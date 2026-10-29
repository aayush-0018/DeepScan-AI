"""Combine CodeBERT (learned) with the AST rules (grounded taint evidence).

- Both agree      -> noisy-OR of the two confidences.
- Only CodeBERT   -> model confidence, slightly discounted.
- Only AST rules  -> rule confidence, discounted because the model disagrees.
"""

from __future__ import annotations

from app.detectors.ast_detector import AstRuleDetector
from app.detectors.base import Hit
from app.detectors.codebert_detector import CodeBertDetector, unit_key
from app.extraction.functions import ParsedFile

ONLY_MODEL_FACTOR = 0.9
ONLY_RULES_FACTOR = 0.8


class EnsembleDetector:
    name = "ensemble"

    def __init__(self, codebert: CodeBertDetector, ast: AstRuleDetector):
        self.codebert = codebert
        self.ast = ast

    @property
    def available(self) -> bool:
        return self.codebert.available

    def detect(self, parsed: ParsedFile) -> list[Hit]:
        scores = self.codebert.score_units(parsed.units)
        model_hits = self.codebert.hits_from_scores(parsed, scores, with_evidence=False)
        rule_hits = self.ast.detect(parsed)

        results: list[Hit] = []
        used_model: set[int] = set()
        for rule in rule_hits:
            sink_line = rule.evidence_lines[-1] if rule.evidence_lines else rule.unit.start_line
            match = None
            for i, model in enumerate(model_hits):
                if i not in used_model and model.unit.start_line <= sink_line <= model.unit.end_line:
                    match = i
                    break
            if match is not None:
                used_model.add(match)
                model = model_hits[match]
                confidence = min(0.99, 1 - (1 - model.confidence) * (1 - rule.confidence))
                pattern = model.pattern if model.confidence >= rule.confidence else rule.pattern
                results.append(
                    Hit(
                        unit=model.unit,
                        pattern=pattern,
                        confidence=round(confidence, 4),
                        vulnerable_probability=round(max(model.vulnerable_probability, rule.confidence), 4),
                        detector=self.name,
                        message=f"{rule.message} CodeBERT agrees ({model.pattern}, p={model.confidence:.2f}).",
                        evidence_lines=rule.evidence_lines,
                        probabilities={**(model.probabilities or {}), "_ast": rule.confidence},
                    )
                )
            else:
                probs = scores.get(unit_key(rule.unit)) or {}
                model_vuln = 1 - probs.get("SAFE", 1.0) if probs else None
                note = f" CodeBERT vulnerable p={model_vuln:.2f}." if model_vuln is not None else ""
                results.append(
                    Hit(
                        unit=rule.unit,
                        pattern=rule.pattern,
                        confidence=round(rule.confidence * ONLY_RULES_FACTOR, 4),
                        vulnerable_probability=round(rule.confidence * ONLY_RULES_FACTOR, 4),
                        detector=self.name,
                        message=rule.message + note,
                        evidence_lines=rule.evidence_lines,
                        probabilities={**probs, "_ast": rule.confidence} if probs else {"_ast": rule.confidence},
                    )
                )

        for i, model in enumerate(model_hits):
            if i in used_model:
                continue
            model.confidence = round(model.confidence * ONLY_MODEL_FACTOR, 4)
            model.detector = self.name
            model.evidence_lines = self.codebert.evidence_lines(model.unit)
            model.probabilities = {**(model.probabilities or {}), "_ast": 0.0}
            results.append(model)
        return results
