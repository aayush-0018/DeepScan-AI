import io
import zipfile

from .conftest import read_fixture


def test_health_reports_no_model_and_offline_llm(client):
    body = client.get("/api/health").json()
    assert body == {"status": "ok", "model_loaded": False, "llm_mode": "offline"}


def test_model_info_falls_back_to_ast(client):
    info = client.get("/api/model-info").json()
    assert info["model_loaded"] is False
    assert info["default_detector"] == "ast"
    assert "SAFE" in info["labels"] and len(info["labels"]) == 7
    assert info["load_error"]


def test_scan_snippet(client):
    resp = client.post("/api/scan", json={"code": read_fixture("template_literal.js"), "filename": "login.js"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["detector"] == "ast"
    assert data["summary"]["total_findings"] == 1
    finding = data["files"][0]["findings"][0]
    assert finding["pattern"] == "TEMPLATE_LITERAL"
    assert finding["severity"] == "high"
    assert finding["id"] == "f_1"
    assert finding["explanation"] is None


def test_scan_with_offline_explanations(client):
    resp = client.post("/api/scan", json={"code": read_fixture("string_concat.js"), "explain": True})
    data = resp.json()
    assert data["summary"]["llm_mode"] == "offline"
    explanation = data["files"][0]["findings"][0]["explanation"]
    assert explanation["source"] == "offline"
    assert "?" in explanation["fix_code"]


def test_scan_safe_code_has_no_findings(client):
    data = client.post("/api/scan", json={"code": read_fixture("safe.js")}).json()
    assert data["summary"]["total_findings"] == 0


def test_codebert_detector_unavailable_returns_409(client):
    resp = client.post("/api/scan", json={"code": "x", "detector": "codebert"})
    assert resp.status_code == 409


def test_regex_detector_selectable(client):
    data = client.post("/api/scan", json={"code": read_fixture("template_literal.js"), "detector": "regex"}).json()
    assert data["summary"]["detector"] == "regex"
    assert data["summary"]["total_findings"] >= 1


def test_scan_files_multipart_and_zip(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/orders.js", read_fixture("orm_raw_query.js"))
        zf.writestr("node_modules/lib/index.js", read_fixture("string_concat.js"))
        zf.writestr("README.md", "# readme")
    files = [
        ("files", ("project.zip", buf.getvalue(), "application/zip")),
        ("files", ("audit.js", read_fixture("second_order.js").encode(), "text/javascript")),
    ]
    resp = client.post("/api/scan/files", files=files, data={"explain": "true"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    scanned = sorted(f["file"] for f in data["files"])
    assert scanned == ["audit.js", "src/orders.js"]
    patterns = sorted(f["pattern"] for fr in data["files"] for f in fr["findings"])
    assert patterns == ["ORM_RAW_QUERY", "SECOND_ORDER"]


def test_scan_files_rejects_unsupported(client):
    resp = client.post("/api/scan/files", files=[("files", ("notes.txt", b"hello", "text/plain"))])
    assert resp.status_code == 400


def test_explain_endpoint(client):
    resp = client.post(
        "/api/explain",
        json={"code": read_fixture("dynamic_identifier.js"), "pattern": "DYNAMIC_IDENTIFIER", "confidence": 0.9},
    )
    body = resp.json()
    assert body["source"] == "offline"
    assert body["false_positive_likelihood"] == "low"
