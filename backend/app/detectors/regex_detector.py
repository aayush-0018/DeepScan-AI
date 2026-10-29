"""v0 baseline: line-based regular expressions.

Kept on purpose as the first step of the regex -> AST -> CodeBERT progression. It is cheap
and catches the obvious cases, but it cannot tell parameterized queries from unsafe ones
when the SQL spans several lines, and it has no notion of where data comes from.
"""

from __future__ import annotations

import re

from app.detectors.base import Hit, innermost_unit, merge_hits_per_unit
from app.extraction.functions import ParsedFile

_SQL = r"(?:\bSELECT\b[\s\S]*?\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b\s+\w+\s+\bSET\b|\bDELETE\s+FROM\b|\bWHERE\b|\bORDER\s+BY\b|\bVALUES\s*\()"
SQL_RE = re.compile(_SQL, re.IGNORECASE)

ORM_RAW_RE = re.compile(
    r"(?:\.(?:raw|whereRaw|orderByRaw|havingRaw|joinRaw|selectRaw|groupByRaw)|\$queryRawUnsafe|\$executeRawUnsafe|sequelize\.query)\s*\("
)
TEMPLATE_INTERP_RE = re.compile(r"`[^`]*\$\{[^`]*`?")
DYNAMIC_IDENT_RE = re.compile(
    r"(?:ORDER\s+BY|GROUP\s+BY|FROM|JOIN|INTO|UPDATE|TABLE)\s*[\"'`]?\s*(?:\$\{|[\"'`]\s*\+)", re.IGNORECASE
)
CONCAT_RE = re.compile(r"""(["'])(?:(?!\1).)*\1\s*\+\s*[A-Za-z_$(]|[A-Za-z_$)\]]\s*\+\s*(["'])""")
FORMAT_RE = re.compile(r"(?:util\.format|sprintf|vsprintf)\s*\(|\.replace(?:All)?\s*\(")
PARAM_HINT_RE = re.compile(r"\?\s*[,)]|\$\d+|:\w+")


class RegexDetector:
    name = "regex"

    @property
    def available(self) -> bool:
        return True

    def detect(self, parsed: ParsedFile) -> list[Hit]:
        lines = parsed.source.decode("utf-8", errors="replace").splitlines()
        hits: list[Hit] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "*", "/*")):
                continue
            # Look at a small window so a SQL string continued on the next line still matches.
            window = " ".join(lines[idx - 1 : idx + 1])
            if not SQL_RE.search(window):
                continue

            pattern = self._classify(line, window)
            if pattern is None:
                continue
            unit = innermost_unit(parsed.units, idx)
            if unit is None:
                continue
            hits.append(
                Hit(
                    unit=unit,
                    pattern=pattern,
                    confidence=0.65 if pattern != "STRING_CONCAT" else 0.6,
                    vulnerable_probability=0.65,
                    detector=self.name,
                    message=f"Regex match on line {idx}: SQL text combined with a dynamic value.",
                    evidence_lines=[idx],
                )
            )
        return merge_hits_per_unit(hits)

    @staticmethod
    def _classify(line: str, window: str) -> str | None:
        has_interp = "${" in line and "`" in window
        has_concat = bool(CONCAT_RE.search(line))
        if ORM_RAW_RE.search(line) and (has_interp or has_concat):
            return "ORM_RAW_QUERY"
        if FORMAT_RE.search(line) and SQL_RE.search(window) and "%s" in window or ".replace" in line and SQL_RE.search(line):
            return "UNSAFE_FORMAT"
        if DYNAMIC_IDENT_RE.search(line):
            return "DYNAMIC_IDENTIFIER"
        if has_interp:
            return "TEMPLATE_LITERAL"
        if has_concat and SQL_RE.search(line):
            return "STRING_CONCAT"
        return None
