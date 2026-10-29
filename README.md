# SQLi Sentinel

SQL injection detection for JavaScript and TypeScript. Source files are split into functions with a
tree-sitter AST, each function is classified as **safe** or as one of **6 SQL injection patterns**, and
findings come back with a confidence score, severity, evidence lines and an optional explanation with a
suggested fix.

The project follows the progression **regex → AST rules → fine-tuned CodeBERT**. All three are
kept behind one detector interface, so they can be compared on the same data.

| Pattern | Example |
|---|---|
| `STRING_CONCAT` | `"SELECT * FROM users WHERE id = " + req.params.id` |
| `TEMPLATE_LITERAL` | `` `... WHERE name = '${name}'` `` |
| `DYNAMIC_IDENTIFIER` | `` `... ORDER BY ${req.query.sort}` `` |
| `ORM_RAW_QUERY` | `sequelize.query(...)`, `knex.raw(...)`, `prisma.$queryRawUnsafe(...)` with interpolation |
| `UNSAFE_FORMAT` | `util.format("... '%s'", x)`, `.replace('{id}', x)` |
| `SECOND_ORDER` | a value read back from the DB concatenated into a new query |

## Status

| Component | State |
|---|---|
| Function-level AST extraction (JS/TS/TSX) | ✅ done |
| Regex baseline, AST taint-rule detector | ✅ done, used by default until a model is trained |
| Dataset generator: 12,465 deduplicated samples, template-grouped splits + held-out set | ✅ done |
| CodeBERT training / calibration / evaluation scripts | ✅ done, smoke-tested with a tiny model; **real training not run yet** |
| FastAPI service (scan, upload, zip, explain) | ✅ done |
| Groq LLM explain mode | ⏳ **placeholder**: offline template explanations until `GROQ_API_KEY` is set |
| React UI (Monaco editor, upload, findings, explanations, export) | ✅ done |
| Tests (pytest, vitest, Postman), Docker | ✅ done |

## Quick start

```bash
make setup          # venv + backend/ML deps + frontend deps, copies .env.example -> .env
make backend        # http://localhost:8000  (docs at /docs)
make frontend       # http://localhost:5173  (proxies /api to :8000)
```

Without a trained model the backend runs in **AST mode**. `detector=auto` picks the ensemble once
`artifacts/model/` exists. Docker: `make docker`, then open http://localhost:8080.

## Enabling Groq explanations

`.env` contains a placeholder:

```
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

While the value is the placeholder, explanations come from `OfflineExplainer` (deterministic,
per-pattern templates) and no network call is made. Paste a real key from https://console.groq.com/keys
and restart the backend. `/api/health` will then report `"llm_mode": "groq"`. If a Groq call fails, the
finding falls back to the offline explanation and says why. The LLM never changes a detector's label.

## Training CodeBERT (later)

```bash
make dataset        # 12,465 samples -> ml/data/processed/{train,val,test,heldout}.jsonl
make train-mps      # Apple Silicon, max_length 256, ~1-3 h
# or open ml/notebooks/colab_train.ipynb on a T4 GPU (~20-30 min at max_length 512)
make evaluate       # regex vs AST vs CodeBERT vs ensemble -> ml/reports/eval.md
```

`ml/train.py` writes the model, tokenizer, `temperature.json` (calibration), `inference_config.json`
and `metrics.json` to `artifacts/model/`. The backend picks it up on restart.

Generalization controls built into the pipeline:
- **Template-grouped splits:** no template/wrapper group appears in both train and test.
- **Held-out set:** built from wrappers (Koa, AWS Lambda), drivers (mssql, pg-promise) and query-building
  variants that never appear in training.
- **Identifier-rename augmentation:** applied at train time (`--augment-prob`).
- **Minimal-edit safe twins and hard negatives:** SQL in logs, allow-lists, `Number()`, `escape()`,
  tagged templates, constant concatenation.
- **Regularization and calibration:** dropout, label smoothing, layer freezing, early stopping on macro-F1,
  and temperature scaling.
- **Shortcut probe:** `evaluate.py --probe-renaming` measures how often predictions flip when only
  variable names change.

### Real-world evaluation set

```bash
make collect-real   # clones OWASP Juice Shop, NodeGoat, DVNA; writes ml/data/real/candidates.jsonl
# review each row: fix `label`, set "reviewed": true
python ml/data/build_dataset.py --real ml/data/real/candidates.jsonl
```

### Current baseline numbers (rule detectors, synthetic data)

| detector | test macro-F1 | held-out macro-F1 |
|---|---|---|
| regex | 0.48 | 0.36 |
| AST rules | 1.00 | 0.998 |

The AST score is **not** a real accuracy figure. The generator and the rules were written together, so
this only shows the labels are consistent. The meaningful numbers will be CodeBERT on the held-out set
and every detector on the reviewed real-world set.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, model loaded, LLM mode |
| GET | `/api/model-info` | labels, device, calibration, metrics, available detectors |
| POST | `/api/scan` | `{code, filename?, language?, detector?, explain?, threshold?}` |
| POST | `/api/scan/files` | multipart `files` (JS/TS files or a `.zip`), `detector`, `explain`, `threshold` |
| POST | `/api/explain` | `{code, pattern, function?, confidence?, evidence_lines?}` |

`detector`: `auto` (default) · `ensemble` · `codebert` · `ast` · `regex`. Asking for
`codebert`/`ensemble` before a model is trained returns `409`.

```bash
curl -s localhost:8000/api/scan -H 'Content-Type: application/json' \
  -d '{"code":"app.get(\"/u\", (req,res)=>db.query(\"SELECT * FROM u WHERE id=\"+req.query.id))","explain":true}'
```

## Tests

```bash
make test                                                     # pytest (31) + vitest (4)
postman collection run postman/SQLi-Sentinel.postman_collection.json   # 11 requests, against a running backend
```

## Layout

```
backend/app/
  extraction/functions.py     tree-sitter -> FunctionUnit (shared by inference and the dataset)
  detectors/regex_detector.py v0 baseline
  detectors/ast_detector.py   v1 intra-function taint rules (sources, propagation, sanitizers, sinks)
  detectors/codebert_detector.py  v2 model: sliding window, temperature, occlusion evidence lines
  detectors/ensemble.py       CodeBERT + AST combination
  llm/groq_explainer.py       Groq client + offline placeholder
  engine.py, report.py, routes/
ml/
  data/generate.py            compositional synthetic generator (wrappers x drivers x shapes x variants)
  data/build_dataset.py       extract -> dedupe -> grouped split -> weak-label check
  data/collect_real.py        mine real repos for an out-of-distribution test set
  augment.py, train.py, evaluate.py, metrics.py, notebooks/colab_train.ipynb
frontend/src/                 React + Vite + Tailwind + Monaco
postman/                      API contract tests
```

## Limitations

- Taint tracking is intra-function. Input passed through helpers in other files is treated as a
  function parameter (lower confidence), not as request data.
- The synthetic data covers common Node.js stacks. Unusual query builders or homegrown DB wrappers
  depend on the CodeBERT model generalizing, which the real-world set is there to measure.
- Code is parsed, never executed. Uploaded zips are read in memory only.
# DeepScan-AI
