"""v2: fine-tuned CodeBERT function classifier.

Loads `artifacts/model` produced by `ml/train.py`. If the directory is missing (model not
trained yet) or torch/transformers are not installed, the detector reports itself as
unavailable and the engine falls back to the AST detector.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from app.detectors.base import Hit
from app.extraction.functions import FunctionUnit, ParsedFile
from app.labels import LABELS

logger = logging.getLogger(__name__)

UnitKey = tuple[int, int, str]


def unit_key(unit: FunctionUnit) -> UnitKey:
    return (unit.start_line, unit.end_line, unit.name)


class CodeBertDetector:
    name = "codebert"

    def __init__(
        self,
        model_dir: Path,
        device: str = "auto",
        batch_size: int = 16,
        occlusion_max_lines: int = 80,
    ):
        self.model_dir = Path(model_dir)
        self.requested_device = device
        self.batch_size = batch_size
        self.occlusion_max_lines = occlusion_max_lines
        self.model = None
        self.tokenizer = None
        self.device: str | None = None
        self.labels: list[str] = list(LABELS)
        self.temperature: float = 1.0
        self.max_length: int = 512
        self.stride: int = 128
        self.metrics: dict | None = None
        self.load_error: str | None = None
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- loading
    @property
    def available(self) -> bool:
        return self.model is not None

    def load(self) -> bool:
        if self.model is not None:
            return True
        if not (self.model_dir / "config.json").exists():
            self.load_error = f"No trained model found in {self.model_dir} (run ml/train.py)."
            logger.info(self.load_error)
            return False
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - depends on install profile
            self.load_error = f"torch/transformers not installed: {exc}"
            logger.warning(self.load_error)
            return False

        try:
            self.device = self._pick_device(torch)
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_dir)
            model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
            model.to(self.device).eval()
            self.model = model
            id2label = getattr(model.config, "id2label", None) or {}
            if id2label:
                self.labels = [id2label[i] if i in id2label else id2label[str(i)] for i in range(len(id2label))]
            self._read_sidecars()
            self.load_error = None
            logger.info("CodeBERT model loaded from %s on %s", self.model_dir, self.device)
            return True
        except Exception as exc:  # noqa: BLE001
            self.model = None
            self.load_error = f"Failed to load model: {exc}"
            logger.exception("Failed to load CodeBERT model")
            return False

    def _pick_device(self, torch) -> str:
        if self.requested_device != "auto":
            return self.requested_device
        if torch.cuda.is_available():
            return "cuda"
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            return "mps"
        return "cpu"

    def _read_sidecars(self) -> None:
        temp_file = self.model_dir / "temperature.json"
        if temp_file.exists():
            self.temperature = float(json.loads(temp_file.read_text()).get("temperature", 1.0))
        cfg_file = self.model_dir / "inference_config.json"
        if cfg_file.exists():
            cfg = json.loads(cfg_file.read_text())
            self.max_length = int(cfg.get("max_length", self.max_length))
            self.stride = int(cfg.get("stride", self.stride))
        metrics_file = self.model_dir / "metrics.json"
        if metrics_file.exists():
            self.metrics = json.loads(metrics_file.read_text())

    # --------------------------------------------------------------- inference
    def predict_texts(self, texts: list[str]) -> list[dict[str, float]]:
        """Class probabilities per text. Long texts use a sliding window; the window with the
        highest vulnerable probability represents the text."""
        if not self.available or not texts:
            return []
        import torch

        with self._lock:
            enc = self.tokenizer(
                texts,
                truncation=True,
                max_length=self.max_length,
                stride=min(self.stride, self.max_length // 4),  # overlap between windows
                return_overflowing_tokens=True,
                padding=True,
                return_tensors="pt",
            )
            mapping = enc.pop("overflow_to_sample_mapping").tolist()
            enc.pop("num_truncated_tokens", None)
            all_probs = []
            n = enc["input_ids"].shape[0]
            with torch.no_grad():
                for start in range(0, n, self.batch_size):
                    batch = {k: v[start : start + self.batch_size].to(self.device) for k, v in enc.items()}
                    logits = self.model(**batch).logits / self.temperature
                    all_probs.append(torch.softmax(logits, dim=-1).float().cpu())
            probs = torch.cat(all_probs).tolist()

        safe_idx = self.labels.index("SAFE") if "SAFE" in self.labels else 0
        best: dict[int, list[float]] = {}
        for window_probs, sample_idx in zip(probs, mapping, strict=True):
            current = best.get(sample_idx)
            if current is None or (1 - window_probs[safe_idx]) > (1 - current[safe_idx]):
                best[sample_idx] = window_probs
        return [dict(zip(self.labels, best[i], strict=True)) for i in range(len(texts))]

    def score_units(self, units: list[FunctionUnit]) -> dict[UnitKey, dict[str, float]]:
        scored = [u for u in units if u.kind != "module" or len(units) == 1]
        probs = self.predict_texts([u.code for u in scored])
        return {unit_key(u): p for u, p in zip(scored, probs, strict=True)}

    def evidence_lines(self, unit: FunctionUnit, top_k: int = 2, min_drop: float = 0.05) -> list[int]:
        """Occlusion: blank each line and measure the drop in vulnerable probability."""
        lines = unit.code.splitlines()
        if not self.available or len(lines) > self.occlusion_max_lines or len(lines) < 2:
            return []
        base = self.predict_texts([unit.code])[0]
        base_vuln = 1 - base.get("SAFE", 0.0)
        variants = []
        for i in range(len(lines)):
            masked = lines.copy()
            masked[i] = ""
            variants.append("\n".join(masked))
        drops = []
        for i, p in enumerate(self.predict_texts(variants)):
            drops.append((base_vuln - (1 - p.get("SAFE", 0.0)), i))
        drops.sort(reverse=True)
        return sorted(unit.start_line + i for drop, i in drops[:top_k] if drop >= min_drop)

    def hits_from_scores(
        self, parsed: ParsedFile, scores: dict[UnitKey, dict[str, float]], with_evidence: bool = True
    ) -> list[Hit]:
        units = {unit_key(u): u for u in parsed.units}
        flagged: list[Hit] = []
        for key, probs in scores.items():
            pattern = max(probs, key=probs.get)
            if pattern == "SAFE":
                continue
            unit = units[key]
            vuln = 1 - probs.get("SAFE", 0.0)
            flagged.append(
                Hit(
                    unit=unit,
                    pattern=pattern,
                    confidence=round(probs[pattern], 4),
                    vulnerable_probability=round(vuln, 4),
                    detector=self.name,
                    message=f"CodeBERT classifies this function as {pattern} "
                    f"(p={probs[pattern]:.2f}, vulnerable p={vuln:.2f}).",
                    probabilities={k: round(v, 4) for k, v in probs.items()},
                )
            )
        # Keep the innermost flagged function when a parent and a nested child are both flagged.
        result = []
        for hit in flagged:
            contains_child = any(
                other is not hit
                and other.unit.start_line >= hit.unit.start_line
                and other.unit.end_line <= hit.unit.end_line
                and other.unit.line_count < hit.unit.line_count
                for other in flagged
            )
            if not contains_child:
                result.append(hit)
        if with_evidence:
            for hit in result:
                hit.evidence_lines = self.evidence_lines(hit.unit)
        return result

    def detect(self, parsed: ParsedFile) -> list[Hit]:
        if not self.available:
            return []
        return self.hits_from_scores(parsed, self.score_units(parsed.units))
