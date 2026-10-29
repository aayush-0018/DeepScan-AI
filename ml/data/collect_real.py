"""Mine real-world JavaScript functions that touch SQL, for an out-of-distribution test set.

  python ml/data/collect_real.py                       # clone default repos, write candidates
  python ml/data/collect_real.py --repo https://github.com/org/app.git --repo ...

Writes ml/data/real/candidates.jsonl. Each candidate is pre-labelled by the AST rule detector
(`suggested_label`) and has `"reviewed": false`. Review by hand: set `label` to the correct
class and `reviewed` to true, then build the dataset with:

  python ml/data/build_dataset.py --real ml/data/real/candidates.jsonl

Only reviewed rows are used, and they always go to the held-out split.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import common  # noqa: E402,F401
from app.detectors.ast_detector import AstRuleDetector  # noqa: E402
from app.extraction.functions import SUPPORTED_EXTENSIONS, parse_source  # noqa: E402

DEFAULT_REPOS = [
    "https://github.com/juice-shop/juice-shop.git",  # OWASP Juice Shop (intentionally vulnerable)
    "https://github.com/OWASP/NodeGoat.git",  # OWASP NodeGoat (intentionally vulnerable)
    "https://github.com/appsecco/dvna.git",  # Damn Vulnerable NodeJS Application
]
SQL_HINT = re.compile(r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b|\.(query|raw|execute)\(", re.IGNORECASE)
SKIP_PARTS = {"node_modules", "dist", "build", "coverage", "test", "tests", "__tests__", "frontend", "vendor"}


def clone(url: str, dest_root: Path) -> Path:
    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    dest = dest_root / name
    if not dest.exists():
        subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], check=True)
    return dest


def candidates_from_repo(repo: Path, max_lines: int) -> list[dict]:
    detector = AstRuleDetector()
    out = []
    for path in sorted(repo.rglob("*")):
        if path.suffix not in SUPPORTED_EXTENSIONS or any(p in SKIP_PARTS for p in path.parts):
            continue
        if path.name.endswith((".min.js", ".d.ts")):
            continue
        try:
            code = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        parsed = parse_source(code, str(path))
        hits = {(h.unit.start_line, h.unit.end_line): h for h in detector.detect(parsed)}
        for unit in parsed.units:
            if unit.kind == "module" or unit.line_count > max_lines or not SQL_HINT.search(unit.code):
                continue
            hit = hits.get((unit.start_line, unit.end_line))
            out.append({
                "code": unit.code,
                "unit_kind": unit.kind,
                "repo": repo.name,
                "file": str(path.relative_to(repo)),
                "function": unit.name,
                "start_line": unit.start_line,
                "suggested_label": hit.pattern if hit else "SAFE",
                "label": hit.pattern if hit else "SAFE",
                "reviewed": False,
            })
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", action="append", help="git URL (repeatable); defaults to OWASP apps")
    parser.add_argument("--local", type=Path, action="append", help="already-cloned directory (repeatable)")
    parser.add_argument("--max-lines", type=int, default=120)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "real" / "candidates.jsonl")
    args = parser.parse_args(argv)

    repos_dir = args.out.parent / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    roots = list(args.local or [])
    if not args.local:
        roots += [clone(url, repos_dir) for url in (args.repo or DEFAULT_REPOS)]

    rows = []
    for root in roots:
        found = candidates_from_repo(root, args.max_lines)
        print(f"{root.name}: {len(found)} SQL-touching functions "
              f"({sum(r['suggested_label'] != 'SAFE' for r in found)} flagged by AST rules)")
        rows.extend(found)
    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"wrote {len(rows)} candidates -> {args.out} (review them, then set reviewed=true)")


if __name__ == "__main__":
    main()
