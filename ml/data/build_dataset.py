"""Build train/val/test/heldout JSONL files.

Steps
  1. generate synthetic samples (ml/data/generate.py)
  2. optionally merge reviewed real-world samples (ml/data/collect_real.py output)
  3. run every sample through the *same* tree-sitter extractor used at inference and keep
     the outermost function unit
  4. deduplicate on an identifier-normalized hash (identifiers -> v1, v2, ...; strings kept)
  5. template-grouped, per-class split so near-identical code never crosses splits
  6. weak-label check: report how often the AST rule detector agrees with the label
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import common  # noqa: E402,F401  (puts backend/ on sys.path; must precede app imports)
from app.detectors.ast_detector import AstRuleDetector  # noqa: E402
from app.extraction.functions import parse_source  # noqa: E402
from common import LABELS, PROCESSED_DIR, read_jsonl, sample_source, write_jsonl  # noqa: E402
from generate import generate  # noqa: E402

IDENT_TYPES = {"identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern"}


def extract_unit(code: str, filename: str = "sample.js") -> tuple[str, str] | None:
    parsed = parse_source(code, filename)
    candidates = [u for u in parsed.units if u.kind != "module"]
    if not candidates:
        return None
    best = max(candidates, key=lambda u: (u.line_count, -u.depth))
    return best.code, best.kind


def normalized_hash(code: str) -> str:
    parsed = parse_source(code, "sample.js")
    names: dict[str, str] = {}
    pieces: list[tuple[int, int, str]] = []
    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in IDENT_TYPES:
            text = node.text.decode()
            names.setdefault(text, f"v{len(names) + 1}")
            pieces.append((node.start_byte, node.end_byte, names[text]))
            continue
        stack.extend(node.children)
    src = parsed.source
    out, last = [], 0
    for start, end, rep in sorted(pieces):
        out.append(src[last:start].decode(errors="replace"))
        out.append(rep)
        last = end
    out.append(src[last:].decode(errors="replace"))
    normalized = " ".join("".join(out).split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def group_split(rows: list[dict], seed: int, val_frac: float, test_frac: float) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    splits: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    by_label: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        by_label[row["label"]][f"{row['template_id']}|{row.get('wrapper', '')}"].append(row)

    for _label, groups in sorted(by_label.items()):
        keys = sorted(groups)
        rng.shuffle(keys)
        total = sum(len(groups[k]) for k in keys)
        targets = {"val": total * val_frac, "test": total * test_frac}
        counts = {"val": 0, "test": 0}
        for key in keys:
            dest = "train"
            for name in ("test", "val"):
                if counts[name] < targets[name] and len(keys) > 2:
                    dest = name
                    break
            if dest != "train":
                counts[dest] += len(groups[key])
            splits[dest].extend(groups[key])
    for rows_ in splits.values():
        rng.shuffle(rows_)
    return splits


def weak_label_agreement(rows: list[dict], limit: int = 3000, seed: int = 0) -> dict:
    detector = AstRuleDetector()
    sample = random.Random(seed).sample(rows, min(limit, len(rows)))
    confusion: Counter = Counter()
    for row in sample:
        hits = detector.detect(parse_source(sample_source(row), "sample.js"))
        pred = max(hits, key=lambda h: h.confidence).pattern if hits else "SAFE"
        confusion[(row["label"], pred)] += 1
    agree = sum(v for (gold, pred), v in confusion.items() if gold == pred)
    binary = sum(v for (gold, pred), v in confusion.items() if (gold == "SAFE") == (pred == "SAFE"))
    per_label = {}
    for label in LABELS:
        tot = sum(v for (g, _), v in confusion.items() if g == label)
        ok = confusion.get((label, label), 0)
        per_label[label] = round(ok / tot, 3) if tot else None
    worst = Counter({k: v for k, v in confusion.items() if k[0] != k[1]}).most_common(8)
    return {
        "n": len(sample),
        "exact_agreement": round(agree / len(sample), 4),
        "binary_agreement": round(binary / len(sample), 4),
        "per_label": per_label,
        "top_disagreements": [f"{g} -> {p}: {v}" for (g, p), v in worst],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=11000)
    parser.add_argument("--heldout-n", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--val-frac", type=float, default=0.1)
    parser.add_argument("--test-frac", type=float, default=0.1)
    parser.add_argument("--real", type=Path, default=None, help="reviewed real-world JSONL (goes to heldout)")
    parser.add_argument("--out-dir", type=Path, default=PROCESSED_DIR)
    parser.add_argument("--skip-agreement", action="store_true")
    args = parser.parse_args(argv)

    raw = generate(args.n, args.heldout_n, args.seed)
    if args.real:
        real = [r for r in read_jsonl(args.real) if r.get("label") in LABELS and r.get("reviewed", True)]
        for r in real:
            r.setdefault("split_hint", "heldout")
            r.setdefault("template_id", f"{r['label']}|real|{r.get('repo', 'unknown')}")
            r["source"] = "real"
        raw.extend(real)
        print(f"merged {len(real)} reviewed real-world samples", file=sys.stderr)

    seen: set[str] = set()
    main_rows, heldout_rows = [], []
    dropped_dupes = dropped_parse = 0
    for row in raw:
        extracted = extract_unit(row["code"], row.get("file", "sample.js"))
        if extracted is None:
            dropped_parse += 1
            continue
        unit, unit_kind = extracted
        h = normalized_hash(unit)
        if h in seen:
            dropped_dupes += 1
            continue
        seen.add(h)
        out = {**row, "code": unit, "unit_kind": unit_kind, "label_id": LABELS.index(row["label"]), "hash": h[:16]}
        (heldout_rows if row.get("split_hint") == "heldout" else main_rows).append(out)

    splits = group_split(main_rows, args.seed, args.val_frac, args.test_frac)
    splits["heldout"] = heldout_rows
    for name, rows in splits.items():
        write_jsonl(args.out_dir / f"{name}.jsonl", rows)

    total = sum(len(r) for r in splits.values())
    print(f"\nkept {total} unique samples (dropped {dropped_dupes} duplicates, {dropped_parse} unparseable)")
    header = f"{'label':<20}" + "".join(f"{s:>9}" for s in splits)
    print(header)
    print("-" * len(header))
    for label in LABELS:
        print(f"{label:<20}" + "".join(f"{sum(1 for r in rows if r['label'] == label):>9}" for rows in splits.values()))
    print(f"{'TOTAL':<20}" + "".join(f"{len(rows):>9}" for rows in splits.values()))

    train_groups = {r["template_id"] for r in splits["train"]}
    test_groups = {r["template_id"] + "|" + r.get("wrapper", "") for r in splits["test"]}
    train_full = {r["template_id"] + "|" + r.get("wrapper", "") for r in splits["train"]}
    print(f"\ntemplate|wrapper groups shared between train and test: {len(train_full & test_groups)} (should be 0)")
    print(f"distinct templates in train: {len(train_groups)}")

    if not args.skip_agreement:
        print("\nWeak-label check (AST rule detector vs generator label):")
        report = weak_label_agreement(splits["train"] + splits["test"])
        for k, v in report.items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
