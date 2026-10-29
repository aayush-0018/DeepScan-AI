from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from app.engine import ModelUnavailableError, ScanEngine
from app.extraction.functions import SUPPORTED_EXTENSIONS
from app.schemas import ScanRequest, ScanResponse

router = APIRouter(prefix="/api", tags=["scan"])

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", "vendor", "__MACOSX"}
MAX_ZIP_RATIO = 50  # reject archives whose uncompressed size is > 50x the upload (zip bombs)


def _engine(request: Request) -> ScanEngine:
    return request.app.state.engine


def _wanted(path: str) -> bool:
    p = PurePosixPath(path)
    if any(part in SKIP_DIRS for part in p.parts) or p.name.startswith("."):
        return False
    if p.name.endswith((".min.js", ".d.ts", ".bundle.js")):
        return False
    return p.suffix.lower() in SUPPORTED_EXTENSIONS


def _decode(data: bytes, name: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail=f"{name} is not valid UTF-8 text") from None


def _read_zip(data: bytes, max_files: int, max_bytes: int) -> list[tuple[str, str]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip archive") from None
    entries = [i for i in archive.infolist() if not i.is_dir() and _wanted(i.filename)]
    total = sum(i.file_size for i in entries)
    if total > max(max_bytes, len(data) * MAX_ZIP_RATIO):
        raise HTTPException(status_code=413, detail="Archive expands to too much data")
    if len(entries) > max_files:
        raise HTTPException(status_code=413, detail=f"Archive has {len(entries)} source files (max {max_files})")
    # Entries are read into memory only, never written to disk, so path traversal names are harmless.
    return [(i.filename, archive.read(i).decode("utf-8", errors="replace")) for i in entries]


def _raise_model_error(exc: ModelUnavailableError):
    raise HTTPException(status_code=409, detail=f"{exc} Use detector='ast' or 'auto'.") from exc


@router.post("/scan", response_model=ScanResponse)
async def scan_code(body: ScanRequest, request: Request) -> ScanResponse:
    try:
        return await _engine(request).scan(
            [(body.filename, body.code)],
            language=body.language,
            detector=body.detector,
            threshold=body.threshold,
            explain=body.explain,
        )
    except ModelUnavailableError as exc:
        _raise_model_error(exc)


@router.post("/scan/files", response_model=ScanResponse)
async def scan_files(
    request: Request,
    files: list[UploadFile] = File(...),
    detector: str | None = Form(default=None),
    explain: bool = Form(default=False),
    threshold: float | None = Form(default=None),
) -> ScanResponse:
    engine = _engine(request)
    settings = engine.settings
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if detector not in (None, "", "auto", "ensemble", "codebert", "ast", "regex"):
        raise HTTPException(status_code=422, detail=f"Unknown detector {detector!r}")

    sources: list[tuple[str, str]] = []
    total = 0
    for upload in files:
        data = await upload.read()
        total += len(data)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail=f"Upload exceeds {settings.max_upload_mb} MB")
        name = upload.filename or "upload.js"
        if name.lower().endswith(".zip"):
            sources.extend(_read_zip(data, settings.max_files, max_bytes))
        elif _wanted(name):
            sources.append((name, _decode(data, name)))
        if len(sources) > settings.max_files:
            raise HTTPException(status_code=413, detail=f"Too many files (max {settings.max_files})")

    if not sources:
        raise HTTPException(
            status_code=400, detail=f"No supported source files found ({', '.join(SUPPORTED_EXTENSIONS)})"
        )
    try:
        return await engine.scan(sources, detector=detector or None, threshold=threshold, explain=explain)
    except ModelUnavailableError as exc:
        _raise_model_error(exc)
