FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv/backend

# CPU-only torch keeps the image small; the model is mounted at /srv/artifacts/model.
ARG INSTALL_ML=true
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install --upgrade pip \
 && if [ "$INSTALL_ML" = "true" ]; then \
      pip install --index-url https://download.pytorch.org/whl/cpu torch && pip install ".[ml]"; \
    else \
      pip install .; \
    fi

ENV MODEL_DIR=/srv/artifacts/model
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
