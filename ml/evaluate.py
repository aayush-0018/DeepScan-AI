"""Compare detectors (regex -> AST rules -> CodeBERT -> ensemble) on the dataset splits.

  python ml/evaluate.py                         # all splits, all available detectors
  python ml/evaluate.py --splits test heldout --detectors ast regex
  python ml/evaluate.py --model-dir ml/runs/smoke-model --probe-renaming

Writes ml/reports/eval.json, ml/reports/eval.md and ml/reports/errors_<detector>_<split>.jsonl.
`--probe-renaming` measures how often CodeBERT changes its prediction when local identifiers
are renamed. A high flip rate means the model learned names, not data flow (shortcut learning).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

import common  # noqa: F401  (puts backend/ on sys.path; must precede app imports)
import numpy as np
from app.detectors.ast_detector import AstRuleDetector
from app.detectors.codebert_detector import CodeBertDetector
from app.detectors.ensemble import EnsembleDetector
from app.detectors.regex_detector import RegexDetector
from app.extraction.functions import parse_source
from common import (
    DEFAULT_MODEL_DIR,
    LABEL2ID,
    LABELS,
    PROCESSED_DIR,
    REPORTS_DIR,
    read_jsonl,
    sample_source,
    write_jsonl,
)
from metrics import classification_report_dict, expected_calibration_error


def rule_predict(detector, rows: list[dict], threshold: float = 0.5) -> list[str]:
    preds = []
    for row in rows:
        hits = [h for h in detector.detect(parse_source(sample_source(row), "sample.js")) if h.confidence >= threshold]
        preds.append(max(hits, key=lambda h: h.confidence).pattern if hits else "SAFE")
    return preds


def codebert_predict(cb: CodeBertDetector, rows: list[dict], batch: int = 64) -> np.ndarray:
    probs = []
    for i in range(0, len(rows), batch):
        chunk = cb.predict_texts([r["code"] for r in rows[i : i + batch]])
        probs.extend([[p[label] for label in LABELS] for p in chunk])
    return np.array(probs)


def report_for(rows, preds, probs=None) -> dict:
    gold = [LABEL2ID[r["label"]] for r in rows]
    pred_ids = [LABEL2ID[p] for p in preds]
    rep = classification_report_dict(gold, pred_ids, probs=probs)
    if probs is not None:
        rep["ece"] = expected_calibration_error(probs, gold)
    return rep


def dump_errors(path: Path, rows, preds, limit: int = 200):
    errors = [
        {"gold": r["label"], "pred": p, "template_id": r.get("template_id"), "wrapper": r.get("wrapper"),
         "driver": r.get("driver"), "code": r["code"]}
        for r, p in zip(rows, preds, strict=True)
        if r["label"] != p
    ]
    write_jsonl(path, errors[:limit])
    return len(errors)


def renaming_probe(cb: CodeBertDetector, rows: list[dict], n: int = 300, seed: int = 0) -> dict:
    from augment import rename_identifiers

    rng = random.Random(seed)
    sample = rng.sample(rows, min(n, len(rows)))
    renamed = [
        {**r, "code": rename_identifiers(r["code"], rng, wrap_class=r.get("unit_kind") == "method")} for r in sample
    ]
    before = codebert_predict(cb, sample).argmax(-1)
    after = codebert_predict(cb, renamed).argmax(-1)
    flips = int(np.sum(before != after))
    return {"n": len(sample), "prediction_flips": flips, "flip_rate": round(flips / max(len(sample), 1), 4)}


def to_markdown(results: dict) -> str:
    lines = ["# SQLi Sentinel — detector comparison", ""]
    for split, by_det in results["splits"].items():
        lines += [f"## {split}", "", "| detector | n | accuracy | macro F1 | binary P | binary R | binary F1 | FP | FN |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for det, rep in by_det.items():
            b = rep["binary"]
            lines.append(f"| {det} | {rep['n']} | {rep['accuracy']:.3f} | {rep['macro_f1']:.3f} | {b['precision']:.3f} | "
                         f"{b['recall']:.3f} | {b['f1']:.3f} | {b['false_positives']} | {b['false_negatives']} |")
        lines.append("")
        for det, rep in by_det.items():
            lines += [f"<details><summary>{det}: per-class F1</summary>", "",
                      "| class | P | R | F1 | support |", "|---|---|---|---|---|"]
            for label, m in rep["per_class"].items():
                lines.append(f"| {label} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['support']} |")
            lines += ["", "</details>", ""]
    if "renaming_probe" in results:
        lines += ["## Shortcut probe (identifier renaming)", "", f"`{json.dumps(results['renaming_probe'])}`", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=Path, default=PROCESSED_DIR)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--splits", nargs="+", default=["test", "heldout"])
    parser.add_argument("--detectors", nargs="+", default=["regex", "ast", "codebert", "ensemble"])
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--limit", type=int, default=None, help="evaluate on at most N samples per split")
    parser.add_argument("--probe-renaming", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=REPORTS_DIR)
    args = parser.parse_args(argv)

    cb = None
    if {"codebert", "ensemble"} & set(args.detectors):
        cb = CodeBertDetector(args.model_dir)
        if not cb.load():
            print(f"[skip] CodeBERT unavailable: {cb.load_error}", file=sys.stderr)
            args.detectors = [d for d in args.detectors if d not in ("codebert", "ensemble")]
            cb = None

    ast, regex = AstRuleDetector(), RegexDetector()
    results: dict = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "splits": {}}
    args.out_dir.mkdir(parents=True, exist_ok=True)

    for split in args.splits:
        path = args.data_dir / f"{split}.jsonl"
        if not path.exists():
            print(f"[skip] {path} not found (run ml/data/build_dataset.py)", file=sys.stderr)
            continue
        rows = read_jsonl(path)
        if args.limit:
            rows = random.Random(0).sample(rows, min(args.limit, len(rows)))
        results["splits"][split] = {}
        for det in args.detectors:
            started = time.time()
            probs = None
            if det == "regex":
                preds = rule_predict(regex, rows, 0.0)
            elif det == "ast":
                preds = rule_predict(ast, rows, args.threshold)
            elif det == "codebert":
                probs = codebert_predict(cb, rows)
                preds = [LABELS[i] for i in probs.argmax(-1)]
            else:
                preds = rule_predict(EnsembleDetector(cb, ast), rows, args.threshold)
            rep = report_for(rows, preds, probs)
            rep["seconds"] = round(time.time() - started, 1)
            rep["errors_dumped"] = dump_errors(args.out_dir / f"errors_{det}_{split}.jsonl", rows, preds)
            results["splits"][split][det] = rep
            print(f"{split:<8} {det:<9} n={rep['n']:<5} acc={rep['accuracy']:.3f} macroF1={rep['macro_f1']:.3f} "
                  f"binF1={rep['binary']['f1']:.3f} FP={rep['binary']['false_positives']} "
                  f"FN={rep['binary']['false_negatives']} ({rep['seconds']}s)")

    if args.probe_renaming and cb is not None:
        rows = read_jsonl(args.data_dir / "test.jsonl")
        results["renaming_probe"] = renaming_probe(cb, rows)
        print("renaming probe:", results["renaming_probe"])

    (args.out_dir / "eval.json").write_text(json.dumps(results, indent=2))
    (args.out_dir / "eval.md").write_text(to_markdown(results))
    print(f"\nreports written to {args.out_dir}")


if __name__ == "__main__":
    main()
