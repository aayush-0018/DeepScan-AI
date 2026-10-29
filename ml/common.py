"""Shared paths + access to the backend package (extractor, detectors, labels)."""

import json
import sys
from pathlib import Path

ML_DIR = Path(__file__).resolve().parent
REPO_ROOT = ML_DIR.parent
BACKEND_DIR = REPO_ROOT / "backend"
DATA_DIR = ML_DIR / "data"
PROCESSED_DIR = DATA_DIR / "processed"
REPORTS_DIR = ML_DIR / "reports"
DEFAULT_MODEL_DIR = REPO_ROOT / "artifacts" / "model"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.labels import ID2LABEL, LABEL2ID, LABELS  # noqa: E402

__all__ = [
    "ML_DIR", "REPO_ROOT", "BACKEND_DIR", "DATA_DIR", "PROCESSED_DIR", "REPORTS_DIR", "DEFAULT_MODEL_DIR",
    "LABELS", "LABEL2ID", "ID2LABEL", "read_jsonl", "write_jsonl", "sample_source",
]


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def sample_source(row: dict) -> str:
    """Source text that parses on its own. Class methods are stored as bare method text
    (exactly what the model sees at inference) and need a class wrapper to re-parse."""
    if row.get("unit_kind") == "method":
        return "class Sample {\n" + row["code"] + "\n}"
    return row["code"]
