# DeepScan AI

**DeepScan AI finds SQL injection vulnerabilities in JavaScript and TypeScript code.** Give it a
snippet, a few files or a zipped project. It reads the code function by function and reports which
functions build SQL queries unsafely. For each one it shows how the injection happens, how confident it
is, which lines are responsible and how to fix it.

It combines three approaches. Each was built to cover what the previous one couldn't:

1. **Regex rules**: fast pattern matching on SQL-looking strings.
2. **AST analysis**: parses the code into a syntax tree and follows untrusted input to the database call.
3. **A fine-tuned CodeBERT model**: a transformer trained on 12,000+ labelled functions. It can classify
   code that doesn't fit any fixed rule.

An optional **LLM explanation mode** (Groq) turns each finding into a plain-English explanation, an
example attack and a suggested fix.

---

## Table of contents

- [Why this project exists](#why-this-project-exists)
- [What it detects](#what-it-detects)
- [How a scan works](#how-a-scan-works)
- [The three detectors](#the-three-detectors)
- [Reading the results](#reading-the-results)
- [LLM explanation mode](#llm-explanation-mode)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Using the web app](#using-the-web-app)
- [API reference](#api-reference)
- [The dataset](#the-dataset)
- [Training the CodeBERT model](#training-the-codebert-model)
- [Evaluation](#evaluation)
- [Project status](#project-status)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Limitations](#limitations)

---

## Why this project exists

SQL injection happens when user input is pasted directly into a SQL query instead of being passed
separately as data. An attacker can then change what the query does. For example:

```js
// The user controls req.params.id
const sql = "SELECT * FROM users WHERE id = " + req.params.id;
await db.query(sql);
```

If someone requests `/users/1 OR 1=1`, the database runs `SELECT * FROM users WHERE id = 1 OR 1=1` and
returns every user. Worse inputs can read password hashes, change data or drop tables.

The fix is usually small: use a placeholder and pass the value separately.

```js
await db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
```

Even so, SQL injection is still one of the most common web vulnerabilities. In Node.js codebases it is
easy to miss because there are so many ways to build a string (`+`, template literals, `util.format`,
`.replace()`, ORM escape hatches), and the input can travel through several variables first.

Simple text search either flags too much (every SQL string) or misses the subtle cases. DeepScan AI
looks at **where data comes from and where it ends up**, and adds a learned model on top for code that
doesn't match fixed rules.

---

## What it detects

Every function gets one of seven labels: **SAFE** or one of the six injection patterns below.

| Pattern | What it means | Vulnerable example | Safe version |
|---|---|---|---|
| `STRING_CONCAT` | Input joined into SQL with `+`, `.concat()` or `.join()` | `"... WHERE id = " + id` | `"... WHERE id = ?", [id]` |
| `TEMPLATE_LITERAL` | Input interpolated into a SQL template string | `` `... WHERE name = '${name}'` `` | placeholder + params, or a tagged `` sql`...` `` template |
| `DYNAMIC_IDENTIFIER` | Input used as a table, column or sort direction. These can't be bound as parameters | `` `... ORDER BY ${req.query.sort}` `` | look the value up in an allow-list |
| `ORM_RAW_QUERY` | Input passed into an ORM's raw-SQL escape hatch | `sequelize.query("..." + x)`, `knex.raw(...)`, `prisma.$queryRawUnsafe(...)` | `replacements` / bindings / `prisma.$queryRaw` tagged template |
| `UNSAFE_FORMAT` | SQL built with string formatting, which does no escaping | `util.format("... '%s'", x)`, `.replace('{id}', x)` | parameterized query |
| `SECOND_ORDER` | A value read back from the database is reused in a new query unsafely | `"... WHERE owner = '" + user.name + "'"` after loading `user` from the DB | parameterize stored values too |

DeepScan AI also recognises common safe patterns, so they aren't flagged:

- parameterized queries for mysql, mysql2, pg, sqlite3, better-sqlite3, mssql and pg-promise
- query builders (`knex(...).where({...})`, Sequelize `findAll`, Prisma `findMany`, TypeORM `findOneBy`)
- allow-lists (`ALLOWED.includes(x)`, lookup maps such as `COLUMNS[req.query.sort]`)
- numeric conversion (`Number()`, `parseInt()`) and escaping (`mysql.escape()`, pg-format `%L`/`%I`)
- tagged templates (`` sql`...` ``, `` Prisma.sql`...` ``)
- SQL that only appears in log messages, comments or concatenated constants

---

## How a scan works

```
  your code
     │
     ▼
┌──────────────────────┐   tree-sitter parses JS / TS / TSX into a syntax tree and
│ 1. Function          │   pulls out every function: declarations, arrow functions,
│    extraction        │   class methods, Express/Koa/Fastify route callbacks,
└──────────┬───────────┘   nested callbacks, plus top-level module code.
           ▼
┌──────────────────────┐   Each function goes to the selected detector:
│ 2. Detection         │   regex · AST rules · CodeBERT · ensemble (CodeBERT + AST).
└──────────┬───────────┘   Each returns a label, a confidence and evidence lines.
           ▼
┌──────────────────────┐   Findings below the confidence threshold are dropped.
│ 3. Report            │   The rest get a severity (high / medium / low), the
└──────────┬───────────┘   function's line range and the lines that caused it.
           ▼
┌──────────────────────┐   Optional: each finding is sent to the explainer, which
│ 4. Explanation       │   returns why it's vulnerable, an example attack and a
└──────────────────────┘   fixed version of the code.
```

Working **per function** is a deliberate choice. A whole file is too much context for a classifier and
a single line is too little. A function usually contains both the place the input arrives and the query
that uses it, so it is the natural unit for spotting injection.

---

## The three detectors

All detectors share one interface, so you can switch between them per scan and compare them on the
same data.

### 1. Regex baseline

Line-by-line regular expressions look for SQL keywords combined with `+`, `${...}`, `util.format`,
`.replace` or ORM raw calls. It is fast and easy to understand. It is also easy to fool: it can't tell a
parameterized query from an unsafe one when the SQL spans several lines, it has no idea where a value
came from, and it can't see second-order injection at all. It is kept as a baseline to show why the
other two exist.

### 2. AST rule detector (taint tracking)

This detector parses each function into a syntax tree and does **lightweight taint tracking** inside
the function:

- **Sources** (untrusted data): request objects (`req.query`, `req.body`, `req.params`, `ctx.request`,
  `event.queryStringParameters`, ...), function parameters, `process.argv`, and values read back from the
  database (for second-order injection).
- **Propagation**: assignments, destructuring, `+`, template literals, `.concat()`, `.join()`,
  `util.format`, `.replace()`, `+=` and common string methods.
- **Sanitizers**: `Number()`, `parseInt()`, `escape()`, allow-list checks, lookups in constant maps,
  tagged templates.
- **Sinks**: `.query()`, `.execute()`, `.raw()`, `.whereRaw()`, `$queryRawUnsafe()` and similar calls
  whose SQL argument was built from tainted data.

The **pattern label comes from how the SQL string was built**. A `+` gives `STRING_CONCAT`. A
`${...}` after `ORDER BY` or `FROM` gives `DYNAMIC_IDENTIFIER`. A raw ORM call gives `ORM_RAW_QUERY`.
Data that came only from the database gives `SECOND_ORDER`. Confidence depends on the source: input
straight from a request (0.95) is more certain than a function parameter (0.85).

Until a CodeBERT model is trained, this is the default detector. It is a capable detector on its own.

### 3. CodeBERT model

[CodeBERT](https://huggingface.co/microsoft/codebert-base) is a 125M-parameter transformer pretrained on
source code. DeepScan AI fine-tunes it as a 7-class classifier (SAFE + the 6 patterns) on the dataset
described below. Compared with the rules it can:

- recognise vulnerable code that uses unfamiliar libraries or helper functions that no rule mentions
- weigh many small signals together instead of needing an exact rule match
- output a **calibrated probability**, adjusted with temperature scaling so that "90% confident" means
  roughly 90%

Functions longer than the model's input limit are scored with a **sliding window**, and the most
suspicious window represents the function. **Evidence lines** are found by occlusion: each line is
blanked in turn, and the lines whose removal lowers the vulnerability score most are the evidence.

### Ensemble (default once a model exists)

The ensemble runs CodeBERT and the AST rules together:

- **Both agree:** confidence is boosted (noisy-OR of the two scores).
- **Only one fires:** the finding is kept, with a discounted confidence.

This pairs the model's coverage with the rules' precise evidence lines.

---

## Reading the results

Each finding contains:

| Field | Meaning |
|---|---|
| `function`, `start_line`–`end_line` | Which function is affected, e.g. `router.get('/users/:id') callback` |
| `pattern` | One of the six injection patterns |
| `confidence` | Probability of that pattern, from 0 to 1 |
| `severity` | `high` (≥ 0.85), `medium` (≥ 0.65) or `low` |
| `evidence_lines` | The lines where the unsafe SQL is built and where it is executed |
| `detectors` | Each detector's score, so you can see whether the model and the rules agree |
| `message` | A one-line summary, e.g. *"SQL built on line 6 from request input reaches `pool.query` on line 7 without parameterization."* |
| `explanation` | (optional) Summary, why it's vulnerable, example attack, suggested fix, false-positive likelihood |

The **confidence threshold** (default 0.5) controls how sensitive the scan is. Lower it to see weaker
signals, raise it to see only the most certain findings.

---

## LLM explanation mode

When **Explain with LLM** is on, each finding gets:

- a **summary** of the problem
- **why it is vulnerable**, referring to the actual variables and lines
- an **example attack** input and the SQL it produces
- a **suggested fix** with corrected code
- the explainer's estimate of how likely the finding is a **false positive**

Explanations come from [Groq](https://groq.com) (default model `llama-3.3-70b-versatile`) once an API
key is configured. Until then, DeepScan AI uses a built-in **offline explainer** with prepared
explanations and fixes for each pattern, and makes no network calls.

```
# .env
GROQ_API_KEY=your_groq_api_key_here      # placeholder -> offline explanations
GROQ_MODEL=llama-3.3-70b-versatile
```

Paste a real key from https://console.groq.com/keys and restart the backend. `/api/health` then reports
`"llm_mode": "groq"`. If a Groq request fails, the finding falls back to the offline explanation and
notes why.

> The LLM only explains. It never changes a detector's verdict, so a model hallucination can't hide or
> invent a finding.

---

## Architecture

```
┌──────────────────────────── React UI (Vite + TypeScript) ────────────────────────────┐
│  Monaco code editor · file/zip upload · detector + threshold + LLM toggle             │
│  summary bar · findings with confidence bars · highlighted lines · explanations       │
│  export report as JSON / Markdown                                                     │
└────────────────────────────────────────┬─────────────────────────────────────────────┘
                                         │ REST / JSON
┌────────────────────────────────────────▼─────────────────────────────────────────────┐
│ FastAPI service                                                                       │
│                                                                                       │
│   /api/scan, /api/scan/files ──► tree-sitter extractor ──► detector                   │
│                                                    ├── RegexDetector                  │
│                                                    ├── AstRuleDetector                │
│                                                    ├── CodeBertDetector (PyTorch)     │
│                                                    └── EnsembleDetector               │
│                                  ──► report builder ──► (optional) explainer          │
│                                                            ├── GroqExplainer          │
│                                                            └── OfflineExplainer       │
└────────────────────────────────────────▲─────────────────────────────────────────────┘
                                         │ loads artifacts/model/
┌────────────────────────────────────────┴─────────────────────────────────────────────┐
│ ML pipeline (offline)                                                                 │
│  generate samples → extract functions → deduplicate → grouped split                   │
│  → fine-tune CodeBERT → calibrate → evaluate against regex / AST → export             │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

The training pipeline uses **the same function extractor** as the live service, so the model is trained
on exactly the kind of input it sees in production.

---

## Tech stack

| Area | Technologies |
|---|---|
| Backend | Python 3.12, FastAPI, Pydantic, Uvicorn |
| Parsing | tree-sitter (JavaScript, TypeScript, TSX grammars) |
| Machine learning | PyTorch, Hugging Face Transformers, CodeBERT, scikit-learn |
| LLM | Groq (OpenAI-compatible chat completions API) |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Monaco Editor |
| Testing | pytest, Vitest, React Testing Library, Postman CLI |
| Deployment | Docker, Docker Compose, nginx |

---

## Getting started

**Requirements:** Python 3.11+, Node.js 20+, and optionally Docker.

```bash
make setup          # creates .venv, installs backend + ML + frontend deps, copies .env.example -> .env
make backend        # API on http://localhost:8000  (interactive docs at /docs)
make frontend       # UI on  http://localhost:5173  (proxies /api to the backend)
```

Or run everything in containers:

```bash
make docker         # UI on http://localhost:8080
```

No trained model is needed to start. Without one, the backend runs in **AST mode**. Once a model is in
`artifacts/model/`, `detector=auto` switches to the ensemble on the next restart.

### Configuration (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `MODEL_DIR` | `artifacts/model` | Where the trained CodeBERT model lives |
| `DEVICE` | `auto` | `auto`, `cpu`, `mps` (Apple Silicon) or `cuda` |
| `DEFAULT_DETECTOR` | `auto` | Detector used when a request doesn't name one |
| `CONFIDENCE_THRESHOLD` | `0.5` | Minimum confidence for a finding to be reported |
| `MAX_UPLOAD_MB`, `MAX_FILES` | `10`, `200` | Upload limits |
| `GROQ_API_KEY`, `GROQ_MODEL` | placeholder | LLM explanation mode |

---

## Using the web app

1. **Paste code** into the editor, or pick one of the built-in samples (Express API, login form,
   Sequelize, `util.format`, second-order, TypeScript service, safe patterns). Or switch to
   **Upload files** and drop `.js` / `.ts` files or a `.zip` of a project. `node_modules`, `dist`,
   `build` and minified files are skipped automatically.
2. Choose a **detector** and **threshold**, and tick **Explain with LLM** if you want explanations.
3. Press **Scan**. Vulnerable functions are highlighted in the editor, with the exact evidence lines
   marked. Click a finding to jump to it.
4. Open **Explain & suggest fix** on any finding, then **Export JSON** or **Export Markdown** to share
   the report.

The header shows whether the CodeBERT model is loaded and whether explanations come from Groq or the
offline placeholder.

---

## API reference

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness, whether the model is loaded, LLM mode |
| GET | `/api/model-info` | Labels, device, calibration temperature, training metrics, available detectors |
| POST | `/api/scan` | Scan a snippet: `{code, filename?, language?, detector?, explain?, threshold?}` |
| POST | `/api/scan/files` | Scan uploads: multipart `files` (JS/TS files or a `.zip`), `detector`, `explain`, `threshold` |
| POST | `/api/explain` | Explain one finding: `{code, pattern, function?, confidence?, evidence_lines?}` |

`detector` can be `auto` (default), `ensemble`, `codebert`, `ast` or `regex`. Requesting `codebert` or
`ensemble` before a model has been trained returns `409 Conflict`.

**Example**

```bash
curl -s localhost:8000/api/scan -H 'Content-Type: application/json' -d '{
  "code": "app.get(\"/u\", (req, res) => db.query(\"SELECT * FROM u WHERE id=\" + req.query.id))",
  "explain": true
}'
```

```json
{
  "summary": { "files_scanned": 1, "functions_scanned": 1, "total_findings": 1,
               "by_severity": { "high": 1, "medium": 0, "low": 0 }, "detector": "ast", "...": "..." },
  "files": [{
    "file": "snippet.js",
    "findings": [{
      "function": "app.get(\"/u\") callback",
      "pattern": "STRING_CONCAT",
      "confidence": 0.95,
      "severity": "high",
      "evidence_lines": [1],
      "message": "SQL built on line 1 from request input reaches `db.query` on line 1 without parameterization.",
      "explanation": { "summary": "...", "attack_example": "...", "fix_code": "...", "source": "offline" }
    }]
  }]
}
```

Uploaded files are parsed in memory and **never executed**. Zip archives are checked for size and file
count before anything is read.

---

## The dataset

Public datasets of labelled JavaScript SQL injection examples are scarce. So DeepScan AI generates its
own: **12,465 deduplicated functions** across the 7 classes, built by combining independent parts:

- **10 code styles:** Express (arrow functions, named handlers, routers), Fastify, Next.js API routes,
  Koa, AWS Lambda, service functions, class methods, callback-style services
- **7 database drivers:** mysql2, mysql (callbacks), pg, sqlite3, better-sqlite3, mssql, pg-promise, plus
  Sequelize, Knex, Prisma and TypeORM for ORM samples
- **Query shapes:** SELECT, INSERT, UPDATE, DELETE, LIKE searches, multi-condition filters, ORDER BY / GROUP
  BY / dynamic tables and columns
- **Construction variants:** inline, via variables, multi-line, built step by step with `+=`, helper
  fragments, `.concat()`, `.join()`, `util.format`, `sprintf`, `.replace()` chains, and more
- **Noise:** input validation, logging, comments, try/catch blocks and renamed variables

The data is designed so the model learns the actual cause of a vulnerability, not shortcuts:

- **Safe twins:** many vulnerable samples have a near-identical safe version, so the only difference
  is whether the query is parameterized.
- **Hard negatives:** safe code that looks dangerous (SQL in log lines, allow-listed identifiers, escaped
  values, tagged templates, constant concatenation).
- **Deduplication** on an identifier-normalised hash, so copies that differ only in variable names don't
  leak between splits.
- **Template-grouped splits:** each template + code-style combination appears in only one of
  train / validation / test.
- **Held-out set** (1,484 samples): uses Koa, AWS Lambda, mssql, pg-promise and construction variants
  that never appear in training. It measures how well the model handles code it has never seen.

| | train | val | test | held-out |
|---|---|---|---|---|
| SAFE | 4,187 | 532 | 544 | 697 |
| each vulnerable pattern | ~700–800 | ~90–120 | ~90–115 | ~110–145 |
| **total** | **8,699** | **1,133** | **1,149** | **1,484** |

### Real-world samples

Synthetic data alone can make a model look better than it is. `make collect-real` clones intentionally
vulnerable open-source apps (**OWASP Juice Shop, NodeGoat, DVNA**) and pulls out every function that
touches SQL. Each one is pre-labelled by the AST detector for you to review by hand. Reviewed samples
always go to the held-out set and are never used for training.

```bash
make collect-real   # writes ml/data/real/candidates.jsonl
# review each row: correct `label`, set "reviewed": true
python ml/data/build_dataset.py --real ml/data/real/candidates.jsonl
```

---

## Training the CodeBERT model

```bash
make dataset        # build ml/data/processed/{train,val,test,heldout}.jsonl
make train-mps      # Apple Silicon (8 GB+): max_length 256, roughly 1–3 hours
make train          # NVIDIA GPU: max_length 512
make evaluate       # compare all detectors, write ml/reports/eval.md
```

No local GPU? Open `ml/notebooks/colab_train.ipynb` in Google Colab on a free T4 GPU (about 20–30
minutes), download the model zip and unpack it into `artifacts/model/`.

Training writes everything the backend needs to `artifacts/model/`: the model weights, the tokenizer,
`temperature.json` (calibration), `inference_config.json` (sequence length and window stride) and
`metrics.json` (results on every split). Restart the backend and it loads automatically.

**Overfitting and generalization controls** in `ml/train.py`:

| Control | Flag | Why |
|---|---|---|
| Identifier-rename augmentation | `--augment-prob` | Stops the model memorising variable names like `userInput` |
| Label smoothing | `--label-smoothing` | Synthetic data is very clean, so this keeps the model from becoming overconfident |
| Dropout | `--dropout` | Regularization |
| Layer freezing | `--freeze-layers N` | Keeps lower pretrained layers stable during the first epoch |
| Class weights | `--class-weights` | Balances SAFE against the six vulnerable classes |
| Early stopping | `--patience` | Stops when validation macro-F1 stops improving |
| Temperature scaling | automatic | Makes confidence scores match real accuracy |

---

## Evaluation

`make evaluate` runs every available detector on the test and held-out sets and writes a comparison
table with per-class precision, recall and F1, binary vulnerable-vs-safe scores, calibration error and
dumps of the worst mistakes.

It also runs a **shortcut probe**: it renames every local variable in the test functions and counts how
often CodeBERT changes its answer. A model that understands data flow shouldn't care what variables are
called, so a high flip rate means it has learned surface cues instead.

### Current numbers (rule-based detectors)

| Detector | Test macro-F1 | Held-out macro-F1 |
|---|---|---|
| Regex | 0.48 | 0.36 |
| AST rules | 1.00 | 0.998 |

The regex baseline drops sharply on unseen code styles, which is why the AST detector was built.

> The AST score is **not** a real-world accuracy figure. The dataset generator and the AST rules were
> written side by side, so a near-perfect score only shows the labels are consistent. The meaningful
> numbers will be **CodeBERT on the held-out set** and **every detector on the reviewed real-world
> samples**.

---

## Project status

| Component | State |
|---|---|
| Function-level AST extraction (JS / TS / TSX) | ✅ Done |
| Regex baseline and AST taint-rule detector | ✅ Done. The AST detector is the default until a model is trained |
| Dataset generator (12,465 samples, grouped splits, held-out set) | ✅ Done |
| CodeBERT training, calibration and evaluation scripts | ✅ Done and smoke-tested. **The real fine-tuning run hasn't been done yet** |
| FastAPI service (scan, upload, zip, explain) | ✅ Done |
| Groq LLM explanation mode | ⏳ Placeholder: offline explanations until `GROQ_API_KEY` is set |
| React web app | ✅ Done |
| Tests (pytest, Vitest, Postman) and Docker | ✅ Done |

---

## Testing

```bash
make test        # backend: pytest (31 tests) · frontend: Vitest (4 tests)

# API contract tests (11 requests) against a running backend:
postman collection run postman/SQLi-Sentinel.postman_collection.json
```

The backend tests include one fixture file per injection pattern plus a file of tricky safe code. Each
pattern must be found, and the safe file must produce no findings.

---

## Project layout

```
backend/
  app/
    extraction/functions.py       tree-sitter → per-function units (shared with the ML pipeline)
    detectors/regex_detector.py   v0: regex baseline
    detectors/ast_detector.py     v1: taint tracking (sources, propagation, sanitizers, sinks)
    detectors/codebert_detector.py v2: model inference, sliding window, calibration, evidence lines
    detectors/ensemble.py         CodeBERT + AST combination
    llm/groq_explainer.py         Groq client + offline placeholder explainer
    engine.py, report.py          scan orchestration, severity, summaries
    routes/                       /api/scan, /api/scan/files, /api/explain, /api/health, /api/model-info
  tests/                          pytest suite + one fixture per pattern
ml/
  data/generate.py                synthetic sample generator
  data/build_dataset.py           extract → deduplicate → grouped split → label check
  data/collect_real.py            real-world sample mining from OWASP apps
  augment.py                      identifier-rename augmentation
  train.py                        CodeBERT fine-tuning + temperature calibration + export
  evaluate.py, metrics.py         detector comparison, shortcut probe, reports
  notebooks/colab_train.ipynb     GPU training on Google Colab
frontend/src/                     React app (editor, uploader, findings, explanations)
postman/                          API contract tests
artifacts/model/                  trained model goes here (not committed)
```

---

## Limitations

- **Analysis stays inside one function.** If request data reaches a query through a helper function in
  another file, DeepScan AI sees it only as a function parameter and reports it with lower confidence.
- **JavaScript and TypeScript only** for now.
- **Training data is mostly synthetic.** It covers common Node.js stacks well. Unusual query builders or
  in-house database wrappers depend on the CodeBERT model generalizing, which the real-world evaluation
  set measures.
- **It finds problems but doesn't fix them.** Suggested fixes are shown for you to apply. Code is never
  modified automatically.
