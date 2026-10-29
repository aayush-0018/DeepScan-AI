PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: setup backend frontend test dataset train train-mps evaluate collect-real postman docker

setup:            ## create venv + install backend/ML deps + frontend deps
	python3 -m venv .venv
	$(PIP) install -e "backend[ml,dev]"
	cd frontend && npm install
	[ -f .env ] || cp .env.example .env

backend:          ## run the API on :8000 (auto-reload)
	cd backend && ../$(PY) -m uvicorn app.main:app --reload --port 8000

frontend:         ## run the UI on :5173 (proxies /api to :8000)
	cd frontend && npm run dev

test:             ## backend + frontend tests
	cd backend && ../$(PY) -m pytest -q
	cd frontend && npm test

dataset:          ## generate + split the 12k-sample dataset
	$(PY) ml/data/build_dataset.py

train:            ## fine-tune CodeBERT (GPU defaults)
	cd ml && ../$(PY) train.py --max-length 512 --batch-size 16 --epochs 4 --augment-prob 0.5 --label-smoothing 0.1

train-mps:        ## fine-tune CodeBERT on Apple Silicon (8 GB)
	cd ml && PYTORCH_ENABLE_MPS_FALLBACK=1 ../$(PY) train.py --max-length 256 --batch-size 8 --grad-accum 4 --epochs 3 --augment-prob 0.5 --label-smoothing 0.1

evaluate:         ## compare regex / AST / CodeBERT / ensemble
	cd ml && ../$(PY) evaluate.py --splits test heldout --probe-renaming

collect-real:     ## clone OWASP vulnerable apps and mine SQL-touching functions for review
	$(PY) ml/data/collect_real.py

postman:          ## run the API collection against a running backend
	postman collection run postman/SQLi-Sentinel.postman_collection.json

docker:           ## build + run backend and frontend (UI on :8080)
	docker compose up --build
