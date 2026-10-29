# SQLi Sentinel — End-to-End Build Plan

A JavaScript/TypeScript SQL injection scanner. Source code is split into functions via AST parsing, each function is classified by a fine-tuned CodeBERT model (safe vs. 6 SQLi patterns), and results are served through a FastAPI inference service with confidence-scored reports, a React UI, and an optional Groq LLM mode that explains each finding.

> **Status (2026-10-29):** Phases 0–3 and 5–8 are implemented (see README). Phase 4's training
> code is written and smoke-tested, but the real CodeBERT fine-tune has not been run yet. Phase 6
> (Groq) is a placeholder: explanations are offline templates until `GROQ_API_KEY` is set in `.env`.

**Stack:** Python 3.12 · FastAPI · PyTorch · HuggingFace Transformers · `microsoft/codebert-base` · tree-sitter (JS/TS AST) · React + Vite + TypeScript · Groq API · Docker

---

## 1. Goals and non-goals

**Goals**
- Scan pasted code, uploaded files, or a zipped project and report vulnerable functions with line ranges, pattern type, and confidence.
- Show the approach evolving across three detectors that all share one interface: **regex → AST rules → CodeBERT**. The first two are kept as baselines and as a fallback.
- Train on 10,000+ labeled function samples across 6 SQLi patterns plus safe code, and measure generalization on a held-out set the model never saw in any form.
- Explain findings in plain English with a suggested fix (Groq LLM mode).

**Non-goals (v1)**
- Languages other than JS/TS.
- Full inter-procedural taint tracking across files (the AST layer does intra-function taint only).
- Auto-fixing code in place.

---

## 2. The 6 SQL injection patterns (label set)

| ID | Label | Example (vulnerable) | Safe counterpart |
|----|-------|----------------------|------------------|
| 0 | `SAFE` | — | `db.query("SELECT * FROM u WHERE id = ?", [id])` |
| 1 | `STRING_CONCAT` | `"SELECT * FROM u WHERE id = " + req.query.id` | placeholder + params array |
| 2 | `TEMPLATE_LITERAL` | `` `SELECT * FROM u WHERE name = '${name}'` `` | tagged template (`sql\`...\``) / params |
| 3 | `DYNAMIC_IDENTIFIER` | `` `ORDER BY ${req.query.sort}` `` / table or column from input | allow-list lookup, `pg-format %I`, `knex.ref` |
| 4 | `ORM_RAW_QUERY` | `sequelize.query(\`... ${x}\`)`, `knex.raw("..." + x)`, `prisma.$queryRawUnsafe(...)` | `replacements` / bindings / `$queryRaw` tagged |
| 5 | `UNSAFE_FORMAT` | `util.format("... %s", x)`, `.replace("{id}", x)`, custom string builders | parameterized query |
| 6 | `SECOND_ORDER` | value read from DB/storage, then concatenated into a new query | re-parameterize stored values |

The model is a 7-class classifier (`SAFE` + 6). "Vulnerable" = any class ≠ 0; confidence = softmax probability of the predicted class. A binary vulnerable probability `1 − p(SAFE)` is also reported.

---

## 3. System architecture

```
                ┌──────────────────────────── React (Vite + TS) ────────────────────────────┐
                │  Monaco editor · file / zip upload · mode toggle (Model | Model + LLM)      │
                │  Findings list · line highlights · confidence bars · LLM explanation panel  │
                └───────────────────────────────┬───────────────────────────────────────────┘
                                                │ REST (JSON / multipart)
┌───────────────────────────────────────────────▼──────────────────────────────────────────────┐
│ FastAPI service                                                                               │
│                                                                                               │
│  /api/scan ─► Extractor (tree-sitter) ─► list[FunctionUnit]                                   │
│                     │                                                                         │
│                     ├─► Detector interface ── RegexDetector   (baseline v0)                   │
│                     │                     ├── AstRuleDetector (baseline v1, taint-lite)       │
│                     │                     └── CodeBertDetector (v2, default)                  │
│                     │                                                                         │
│                     ├─► Ensemble/aggregator ─► Report (per function + per file + summary)     │
│                     └─► (mode=llm) GroqExplainer ─► explanation + fix per finding             │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
         ▲
         │ loads model weights from ./artifacts/model (exported after training)
┌────────┴─────────────────────────────────────────────────────────────────────┐
│ ML pipeline (offline): generate data → extract functions → dedupe → split    │
│   → fine-tune CodeBERT → evaluate (in-dist + held-out) → export artifacts    │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Repository layout

```
SQLxW/
├── PLAN.md
├── README.md
├── docker-compose.yml
├── .env.example                 # GROQ_API_KEY, MODEL_DIR, DEVICE
├── backend/
│   ├── pyproject.toml
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, lifespan (model load)
│   │   ├── config.py            # pydantic-settings
│   │   ├── schemas.py           # request/response models
│   │   ├── routes/
│   │   │   ├── scan.py          # /api/scan, /api/scan/files
│   │   │   ├── explain.py       # /api/explain
│   │   │   └── health.py        # /api/health, /api/model-info
│   │   ├── extraction/
│   │   │   └── functions.py     # tree-sitter JS/TS → FunctionUnit
│   │   ├── detectors/
│   │   │   ├── base.py          # Detector protocol
│   │   │   ├── regex_detector.py
│   │   │   ├── ast_detector.py
│   │   │   └── codebert_detector.py
│   │   ├── report.py            # aggregation, severity, summary
│   │   └── llm/groq_explainer.py
│   └── tests/
├── ml/
│   ├── data/
│   │   ├── templates/           # vulnerable + safe templates per pattern
│   │   ├── generate.py          # synthetic generator (10k+)
│   │   ├── collect_real.py      # optional: scrape/curate real snippets
│   │   ├── build_dataset.py     # extract → normalize → dedupe → split
│   │   └── processed/           # train/val/test/heldout .jsonl
│   ├── train.py                 # HF Trainer fine-tuning
│   ├── evaluate.py              # metrics, confusion matrix, error analysis
│   ├── export.py                # save tokenizer + model (+ optional ONNX)
│   └── notebooks/
│       └── colab_train.ipynb    # GPU training option
├── artifacts/model/             # trained weights (git-ignored)
└── frontend/
    ├── package.json
    └── src/
        ├── api.ts
        ├── App.tsx
        └── components/ (Editor, Uploader, FindingsList, FindingCard, ExplanationPanel, SummaryBar)
```

---

## 5. Phase-by-phase implementation

### Phase 0 — Scaffolding (½ day)
- Init git, Python venv (`uv` or `venv`), `backend/pyproject.toml`, Vite React-TS app in `frontend/`.
- Shared `.env.example`, `.gitignore` (weights, datasets, `node_modules`, `.venv`).
- Pre-commit: `ruff`, `black`, `eslint`, `prettier`.

### Phase 1 — Regex baseline (v0) (½ day)
- `RegexDetector`: patterns for SQL keywords (`SELECT|INSERT|UPDATE|DELETE ... FROM|INTO|SET|WHERE`) combined with `+`, `${}`, `util.format`, `.raw(`, `.query(`, `$queryRawUnsafe`.
- Purpose: a baseline number for the evaluation table, and to record its failure modes (false positives on parameterized queries that still contain `+` across lines, false negatives on SQL built across several statements).

### Phase 2 — AST function extraction + rule detector (v1) (1½ days)
**Extractor** (`tree-sitter` + `tree-sitter-javascript` / `tree-sitter-typescript`):
- Walk the tree and collect `function_declaration`, `function_expression`, `arrow_function`, `method_definition`, `generator_function_declaration`; anonymous callbacks (e.g. Express handlers `app.get('/x', async (req,res)=>{...})`) are included and named from context (`GET /x handler`).
- Nested functions are emitted on their own **and** remain part of the parent's text; the report de-duplicates overlapping findings by keeping the innermost.
- Top-level code outside functions becomes a synthetic `<module>` unit.
- `FunctionUnit = {name, kind, start_line, end_line, code, file}`.

**AstRuleDetector (taint-lite, intra-function):**
- Sources: `req.query|body|params|headers|cookies`, function parameters, `process.argv`, values read from DB results (for second-order).
- Propagation: assignments, destructuring, template literals, `+`, `.concat`, `.join`, `util.format`, `.replace`.
- Sinks: `.query`, `.execute`, `.raw`, `sequelize.query`, `$queryRawUnsafe`, `$executeRawUnsafe`, `db.exec`, `pool.query`, etc.
- Flag when a tainted value reaches a sink's SQL-string argument without going through a parameter array. Pattern label comes from *how* it was built (concat / template / format / identifier position / ORM raw).
- This is also used as a **weak labeler** to check generated data and to mine real-world samples.

### Phase 3 — Dataset (2–3 days) → 10,000+ function samples

**Sources**
1. **Synthetic generator** (main source, ~8–9k): per pattern, 15–30 vulnerable templates and matching safe templates, filled from randomized pools:
   - DB drivers: `mysql`, `mysql2`, `pg`, `sqlite3`, `better-sqlite3`, `mssql`, `sequelize`, `knex`, `typeorm`, `prisma`.
   - Code style: callbacks / promises / async-await, CommonJS / ESM, Express / Koa / Fastify / Next.js API route handlers, TS type annotations on/off.
   - Identifiers: random realistic names (not always `userInput`), table/column names from a vocabulary, SQL with varied clauses, casing, whitespace and line breaks.
   - Noise: unrelated statements, logging, validation that *looks* like sanitization but isn't (e.g. `.trim()`), and real sanitization (`parseInt`, allow-lists, `escape()`), so the model learns the difference.
2. **Hard negatives** (~1.5k): code with SQL keywords that is safe — parameterized queries, query builders (`knex.where({id})`), SQL in log messages or comments, constant-only concatenation (`"SELECT " + COLUMNS + " FROM t"` where `COLUMNS` is a constant).
3. **Real-world snippets** (optional, ~300–1k): small curated set from public vulnerable-by-design apps (OWASP Juice Shop, NodeGoat, DVNA) plus safe code from popular OSS repos, labeled by the AST detector + manual review. **This forms the out-of-distribution test set.**

**Processing (`build_dataset.py`)**
- Run every sample through the same AST extractor used at inference, so training and inference see identical function units.
- Normalize whitespace; strip comments optionally (as an augmentation flag).
- **Deduplicate** on a normalized hash (identifiers renamed to `v1, v2…`) so near-identical copies don't leak across splits.
- **Template-grouped split:** each template family goes into exactly one of train / val / test. A separate **held-out set** uses templates, drivers, and frameworks never seen in training, plus the real-world snippets. This is the honest generalization number.
- Target class balance: ~40% SAFE, ~10% per vulnerable class.
- Output: `train.jsonl`, `val.jsonl`, `test.jsonl`, `heldout.jsonl` with `{code, label, pattern, template_id, driver, source}`.

### Phase 4 — CodeBERT fine-tuning (v2) (2 days incl. iteration)
- Model: `microsoft/codebert-base` (RoBERTa, 125M params) + classification head (7 classes), via `AutoModelForSequenceClassification`.
- Input: function code, `max_length=512`. Longer functions are split with a **sliding window** (stride 256) and scored by max-pooling vulnerable probability across windows.
- Training (HF `Trainer`): lr 2e-5, batch 16 (grad-accum on M1), 3–5 epochs, warmup 10%, weight decay 0.01, early stopping on val macro-F1, class-weighted loss if imbalance remains.
- **Hardware:** this machine is an Apple M1 with 8 GB RAM. Training runs on PyTorch `mps` with `max_length=256`, batch 4–8 and grad accumulation (~1–3 h). A Colab notebook (T4 GPU, ~20–30 min) is provided as the faster path. Inference runs fine on CPU/MPS.

**Overfitting and generalization: planned work**
The first model will probably score ~99% on the in-distribution test set and much lower on held-out data. These are the fixes to apply and measure one by one, and the evaluation report records each change:
1. **Shortcut detection:** check whether the model keys on identifier names (`userInput`, `req.query`) or driver names. Test: swap identifiers and compare predictions.
2. **Identifier randomization / renaming augmentation** at train time.
3. **Paired contrastive samples:** every vulnerable template has a minimal-edit safe twin (same code, parameterized), so the decision boundary sits on the actual cause.
4. **Hard negatives** (above) to cut false positives on SQL-looking safe code.
5. **Regularization:** dropout 0.1→0.2, fewer epochs, freeze the lower 6 encoder layers for epoch 1, label smoothing 0.1.
6. **Template-grouped splits** so validation measures generalization, not memorization.

**Evaluation (`evaluate.py`)**
- Per-class precision / recall / F1, macro-F1, binary vulnerable-vs-safe F1, ROC-AUC, confusion matrix.
- Separate numbers for in-dist test and held-out.
- Calibration check (reliability diagram / ECE); apply **temperature scaling** on val so confidence scores mean something.
- Comparison table: Regex vs AST rules vs CodeBERT vs ensemble (CodeBERT + AST agreement boost).
- Error analysis dump: top false positives and false negatives with code.

**Export (`export.py`)**: `save_pretrained` to `artifacts/model/` along with `label_map.json`, `temperature.json`, and `metrics.json`. Optional ONNX export for faster CPU inference.

### Phase 5 — FastAPI inference service (1½ days)
- Model loaded once in the `lifespan` handler; device auto-select (`cuda` → `mps` → `cpu`); batched inference over all functions in a request.
- **Endpoints**

| Method | Path | Body | Purpose |
|--------|------|------|---------|
| GET | `/api/health` | — | liveness + model loaded |
| GET | `/api/model-info` | — | version, labels, metrics snapshot |
| POST | `/api/scan` | `{code, filename?, language?, detector?: "codebert"\|"ast"\|"regex"\|"ensemble", explain?: bool, threshold?: float}` | scan pasted code |
| POST | `/api/scan/files` | multipart: files or one `.zip` | scan many files / a project |
| POST | `/api/explain` | `{finding_id \| code, pattern}` | on-demand LLM explanation |

- **Report schema (per finding):**
```json
{
  "id": "f_3",
  "file": "routes/user.js",
  "function": "getUser",
  "start_line": 12, "end_line": 24,
  "pattern": "TEMPLATE_LITERAL",
  "confidence": 0.94,
  "vulnerable_probability": 0.97,
  "severity": "high",
  "evidence_lines": [17],
  "detectors": {"codebert": 0.94, "ast": true},
  "explanation": null
}
```
- `severity` comes from confidence plus pattern (e.g. ≥0.85 high, 0.6–0.85 medium, threshold–0.6 low).
- `evidence_lines`: from the AST detector's sink location when available; otherwise found by occlusion (mask each line and measure the drop in probability), computed only for flagged functions.
- Summary block: files scanned, functions scanned, counts by severity / pattern, scan time.
- Limits: max upload size, max files, max function count, request timeout. Zip extraction guards against path traversal and zip bombs. Code is never executed.

### Phase 6 — Groq LLM explain mode (½ day)
- `GroqExplainer` uses the `groq` Python SDK; model is configurable (default `llama-3.3-70b-versatile`); key from `GROQ_API_KEY`.
- Only flagged functions are sent. The prompt includes the function code, the predicted pattern, confidence, and evidence lines. It asks for structured JSON output: `{summary, why_vulnerable, attack_example, fix_code, false_positive_likelihood}`.
- The LLM explains and is **not** the judge: its output never changes the model's label. A `false_positive_likelihood` from the LLM is shown as a separate signal.
- Concurrency with `asyncio.gather` plus a semaphore; per-finding cache keyed by code hash; graceful degradation if the key is missing or rate-limited (findings still return, `explanation: null` with a reason).

### Phase 7 — React frontend (2 days)
- Vite + React + TypeScript, Tailwind for styling, `@monaco-editor/react` for the editor.
- **Views:** a Scan page with an editor tab and an upload tab (files / zip), detector selector, "Explain with LLM" toggle, and confidence threshold slider.
- **Results:** summary bar (counts by severity), findings list sorted by severity, line decorations in Monaco on vulnerable ranges and evidence lines, a confidence bar per finding, and an expandable explanation panel with a fixed-code diff view.
- Export the report as JSON / Markdown.
- Sample snippets dropdown (one per pattern plus safe ones) for demos.

### Phase 8 — Testing, packaging, docs (1 day)
- **Backend tests (pytest):** extractor on tricky syntax (arrow functions, classes, TS generics, JSX), each detector on golden fixtures (one per pattern plus hard negatives), API contract tests with `httpx.AsyncClient`, Groq client mocked.
- **ML sanity tests:** the model loads, predicts on the 7 golden fixtures correctly, and inference stays under a latency budget.
- **Frontend:** a couple of Vitest component tests; a Playwright smoke test (optional).
- **Postman collection** for the API (Postman CLI is installed), run in CI with `postman collection run`.
- **Docker:** `backend` image (CPU torch, model mounted as a volume), `frontend` image (nginx static), `docker-compose.yml`.
- **README:** architecture diagram, how to train, how to run, evaluation table (regex vs AST vs CodeBERT, in-dist vs held-out), and known limitations.

---

## 6. Timeline (approx.)

| Phase | Effort |
|-------|--------|
| 0 Scaffolding | 0.5 d |
| 1 Regex baseline | 0.5 d |
| 2 AST extraction + rules | 1.5 d |
| 3 Dataset (10k+) | 2–3 d |
| 4 CodeBERT training + generalization iterations | 2 d |
| 5 FastAPI service | 1.5 d |
| 6 Groq explain mode | 0.5 d |
| 7 React UI | 2 d |
| 8 Tests, Docker, docs | 1 d |
| **Total** | **~11–12 working days** |

Build order: 0 → 2 (extractor is shared by everything) → 1 → 3 → 5 (wired to the AST detector first so the API/UI work isn't blocked on training) → 7 → 4 → 6 → 8.

---

## 7. Key dependencies

**Backend / ML:** `fastapi`, `uvicorn[standard]`, `pydantic-settings`, `python-multipart`, `torch`, `transformers`, `datasets`, `accelerate`, `scikit-learn`, `tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript`, `groq`, `pytest`, `httpx`, `ruff`.
**Frontend:** `react`, `vite`, `typescript`, `@monaco-editor/react`, `tailwindcss`, `axios` (or `fetch`), `vitest`.

---

## 8. Success criteria

- ≥10,000 deduplicated function samples across 7 classes, with template-grouped splits.
- CodeBERT macro-F1 ≥ 0.95 on in-dist test and **≥ 0.85 on held-out**, beating both baselines on held-out.
- Binary vulnerable-vs-safe recall ≥ 0.90 on the real-world snippet set.
- `/api/scan` on a 300-line file returns in < 1.5 s on CPU (without LLM).
- The UI shows highlighted findings with confidence and LLM explanations end to end.

---

## 9. Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Synthetic data is too clean, so the model doesn't transfer to real code | real-world held-out set, noise injection, more drivers/frameworks, AST-assisted mining of real code |
| Model learns shortcuts (variable names, driver names) | identifier randomization, paired safe twins, shortcut probes |
| Functions longer than 512 tokens | sliding window + max-pool |
| M1 / 8 GB memory limits during training | `max_length=256`, small batch + grad accumulation, Colab notebook as fallback |
| Overconfident softmax | temperature scaling + reliability check |
| LLM hallucinated fixes | LLM is advisory only, its output is structured, and the UI labels it clearly as AI-generated |

---

## 10. Decisions to confirm before implementation

1. **Training hardware:** train locally on the M1 (slower, `max_length=256`) or use the Colab notebook on a GPU? Default: build both and run locally first.
2. **TypeScript support** in v1 (same extractor, small extra cost)? Default: yes.
3. **Real-world snippet set:** include the curated OWASP Juice Shop / NodeGoat / DVNA samples for the held-out evaluation? Default: yes.
4. **Groq API key:** available now, or should the LLM mode be mocked until it is?
