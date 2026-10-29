"""Explanations for findings.

- `OfflineExplainer`: deterministic, template-based. Used while GROQ_API_KEY is the placeholder
  value in .env, and as the fallback when the Groq call fails.
- `GroqExplainer`: calls Groq's OpenAI-compatible chat completions endpoint. Enabled
  automatically once a real key is set in .env.

The LLM only explains and suggests a fix; it never changes the detector's label.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re

import httpx

from app.config import Settings
from app.labels import PATTERN_DESCRIPTIONS
from app.schemas import Explanation

logger = logging.getLogger(__name__)

_FIXES: dict[str, dict[str, str]] = {
    "STRING_CONCAT": {
        "why": "The query text is assembled with string concatenation, so whatever the caller sends becomes "
        "part of the SQL grammar instead of being treated as data.",
        "attack": "id = \"1 OR 1=1\"  ->  SELECT * FROM users WHERE id = 1 OR 1=1  (returns every row)",
        "fix": "// Use placeholders and pass values separately\n"
        "const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);\n"
        "// pg:   await client.query('SELECT * FROM users WHERE id = $1', [id]);",
    },
    "TEMPLATE_LITERAL": {
        "why": "Interpolating a value with ${...} inside a SQL template literal is string concatenation in "
        "disguise; quotes in the input close the SQL string and inject new clauses.",
        "attack": "name = \"' OR '1'='1\"  ->  ... WHERE name = '' OR '1'='1'",
        "fix": "// Replace the interpolation with a placeholder\n"
        "const [rows] = await db.query('SELECT * FROM users WHERE name = ?', [name]);\n"
        "// or a tagged template that parameterizes: sql`SELECT * FROM users WHERE name = ${name}`",
    },
    "DYNAMIC_IDENTIFIER": {
        "why": "Identifiers (table names, columns, ORDER BY / sort direction) cannot be bound as parameters, "
        "so passing user input there lets an attacker rewrite the query structure.",
        "attack": "sort = \"(CASE WHEN (SELECT 1 FROM admins LIMIT 1)=1 THEN id ELSE name END)\"  "
        "->  blind data extraction through ORDER BY",
        "fix": "const SORTABLE = { name: 'name', created: 'created_at' };\n"
        "const column = SORTABLE[req.query.sort] ?? 'created_at';\n"
        "const dir = req.query.dir === 'asc' ? 'ASC' : 'DESC';\n"
        "const [rows] = await db.query(`SELECT * FROM users ORDER BY ${column} ${dir}`);",
    },
    "ORM_RAW_QUERY": {
        "why": "ORMs are only safe while you use their query builders. Raw-SQL escape hatches "
        "(sequelize.query, knex.raw, $queryRawUnsafe) run the string as-is, so interpolated input is injectable.",
        "attack": "email = \"x' UNION SELECT password FROM users --\"  ->  leaks password hashes",
        "fix": "// Sequelize\nawait sequelize.query('SELECT * FROM users WHERE email = :email', "
        "{ replacements: { email }, type: QueryTypes.SELECT });\n"
        "// Knex\nawait knex.raw('SELECT * FROM users WHERE email = ?', [email]);\n"
        "// Prisma\nawait prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;",
    },
    "UNSAFE_FORMAT": {
        "why": "util.format / %s / .replace() substitute raw text into the SQL string. They do no escaping, "
        "so this is equivalent to concatenation.",
        "attack": "id = \"0; DROP TABLE orders; --\"  ->  stacked query if the driver allows multiple statements",
        "fix": "// Drop the formatter; let the driver bind the value\n"
        "await db.query('SELECT * FROM orders WHERE id = ?', [id]);\n"
        "// For identifiers use pg-format %I / mysql.escapeId, never %s",
    },
    "SECOND_ORDER": {
        "why": "A value that was stored earlier (for example a username saved at sign-up) is read back from "
        "the database and concatenated into a new query. Data from your own DB is still attacker-controlled "
        "if it originally came from a user.",
        "attack": "Register username \"admin'--\"; later  ... WHERE owner = 'admin'--'  targets the admin account",
        "fix": "const [[user]] = await db.query('SELECT username FROM users WHERE id = ?', [userId]);\n"
        "await db.query('SELECT * FROM audit_log WHERE owner = ?', [user.username]);",
    },
}


def _fp_likelihood(confidence: float | None) -> str:
    if confidence is None:
        return "medium"
    if confidence >= 0.85:
        return "low"
    if confidence >= 0.65:
        return "medium"
    return "high"


class OfflineExplainer:
    mode = "offline"

    def __init__(self, note: str | None = None):
        self.note = note or "Offline explanation (set GROQ_API_KEY in .env to enable Groq LLM explanations)."

    async def explain(
        self,
        code: str,
        pattern: str,
        function: str,
        confidence: float | None = None,
        evidence_lines: list[int] | None = None,
    ) -> Explanation:
        info = _FIXES.get(pattern)
        if info is None:
            return Explanation(
                summary=f"`{function}` was not classified as vulnerable.",
                why_vulnerable="No unsafe SQL construction was identified.",
                attack_example="",
                fix_code="",
                false_positive_likelihood="high",
                source="offline",
                note=self.note,
            )
        where = f" (see line{'s' if evidence_lines and len(evidence_lines) > 1 else ''} " \
            f"{', '.join(map(str, evidence_lines))})" if evidence_lines else ""
        return Explanation(
            summary=f"`{function}` is likely vulnerable to SQL injection: {PATTERN_DESCRIPTIONS[pattern]}{where}",
            why_vulnerable=info["why"],
            attack_example=info["attack"],
            fix_code=info["fix"],
            false_positive_likelihood=_fp_likelihood(confidence),
            source="offline",
            note=self.note,
        )


SYSTEM_PROMPT = """You are an application security reviewer specialised in SQL injection in JavaScript/TypeScript.
A detector has flagged a function. Explain the finding to a developer and propose a minimal fix.
Respond ONLY with a JSON object with these keys:
  "summary": one sentence,
  "why_vulnerable": 2-4 sentences referencing the actual variables and lines,
  "attack_example": a concrete malicious input and the resulting SQL,
  "fix_code": the corrected function (JavaScript), using parameterized queries or allow-lists,
  "false_positive_likelihood": "low" | "medium" | "high" (your estimate that the detector is wrong).
Do not invent code that is not in the function."""


class GroqExplainer:
    mode = "groq"

    def __init__(self, settings: Settings):
        self.settings = settings
        self.fallback = OfflineExplainer(note="Groq request failed; showing offline explanation.")
        self._cache: dict[str, Explanation] = {}
        self._semaphore = asyncio.Semaphore(settings.groq_max_concurrency)

    async def explain(
        self,
        code: str,
        pattern: str,
        function: str,
        confidence: float | None = None,
        evidence_lines: list[int] | None = None,
    ) -> Explanation:
        key = hashlib.sha256(f"{pattern}\0{code}".encode()).hexdigest()
        if key in self._cache:
            return self._cache[key]

        user_prompt = (
            f"Function: {function}\nDetected pattern: {pattern} ({PATTERN_DESCRIPTIONS.get(pattern, '')})\n"
            f"Detector confidence: {confidence if confidence is not None else 'n/a'}\n"
            f"Evidence lines: {evidence_lines or 'n/a'}\n\n```javascript\n{code[:12000]}\n```"
        )
        payload = {
            "model": self.settings.groq_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.settings.groq_api_key}"}
        try:
            async with self._semaphore, httpx.AsyncClient(timeout=self.settings.groq_timeout_seconds) as client:
                resp = await client.post(
                    f"{self.settings.groq_base_url.rstrip('/')}/chat/completions", json=payload, headers=headers
                )
                resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            data = _parse_json(content)
            fp = str(data.get("false_positive_likelihood", "medium")).lower()
            explanation = Explanation(
                summary=str(data.get("summary", "")),
                why_vulnerable=str(data.get("why_vulnerable", "")),
                attack_example=str(data.get("attack_example", "")),
                fix_code=str(data.get("fix_code", "")),
                false_positive_likelihood=fp if fp in ("low", "medium", "high") else "medium",
                source="groq",
                model=self.settings.groq_model,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq explanation failed: %s", exc)
            explanation = await self.fallback.explain(code, pattern, function, confidence, evidence_lines)
            explanation.note = f"Groq request failed ({type(exc).__name__}); showing offline explanation."
            return explanation
        self._cache[key] = explanation
        return explanation


def _parse_json(content: str) -> dict:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            return json.loads(match.group(0))
        raise


def get_explainer(settings: Settings) -> OfflineExplainer | GroqExplainer:
    return GroqExplainer(settings) if settings.groq_enabled else OfflineExplainer()
