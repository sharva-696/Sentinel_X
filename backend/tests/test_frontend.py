import io
import re
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.config import BACKEND_DIR
from backend.tests.test_analysis import create_synthetic_esp32_binary

FRONTEND_DIR = BACKEND_DIR.parent / "frontend"


def test_frontend_files_exist_on_disk():
    """Verifies that all frontend assets and component modules exist in repository."""
    expected_files = [
        FRONTEND_DIR / "index.html",
        FRONTEND_DIR / "css" / "styles.css",
        FRONTEND_DIR / "js" / "app.js",
        FRONTEND_DIR / "js" / "api.js",
        FRONTEND_DIR / "js" / "state.js",
        FRONTEND_DIR / "js" / "components" / "nav.js",
        FRONTEND_DIR / "js" / "components" / "overview.js",
        FRONTEND_DIR / "js" / "components" / "analyze.js",
        FRONTEND_DIR / "js" / "components" / "history.js",
        FRONTEND_DIR / "js" / "components" / "detail.js",
        FRONTEND_DIR / "js" / "components" / "devices.js",
    ]
    for path in expected_files:
        assert path.is_file(), f"Expected frontend file missing: {path}"


def test_fastapi_serves_frontend_dashboard(client: TestClient):
    """Verifies that FastAPI serves the index.html on /dashboard/."""
    res = client.get("/dashboard/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Sentinel-X" in res.text
    assert 'rel="stylesheet" href="css/styles.css"' in res.text
    assert 'type="module" src="js/app.js"' in res.text


def test_fastapi_serves_frontend_css_and_js_modules(client: TestClient):
    """Verifies correct MIME types for styles.css and JavaScript ES modules."""
    css_res = client.get("/dashboard/css/styles.css")
    assert css_res.status_code == 200
    assert "text/css" in css_res.headers["content-type"]
    assert "--sev-crit-fg" in css_res.text

    js_files = [
        "js/app.js",
        "js/api.js",
        "js/state.js",
        "js/components/nav.js",
        "js/components/overview.js",
        "js/components/analyze.js",
        "js/components/history.js",
        "js/components/detail.js",
        "js/components/devices.js",
    ]
    for js_path in js_files:
        js_res = client.get(f"/dashboard/{js_path}")
        assert js_res.status_code == 200, f"Failed to load {js_path}"
        assert any(t in js_res.headers["content-type"] for t in ["javascript", "text/plain"])


def test_root_endpoint_references_dashboard(client: TestClient):
    """Verifies root API endpoint directs users to the interactive dashboard URL."""
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["dashboard_url"] == "/dashboard/"


def test_frontend_html_accessibility_and_safety():
    """Verifies accessibility attributes, skip-to-content link, and safe markup in index.html."""
    html_path = FRONTEND_DIR / "index.html"
    content = html_path.read_text(encoding="utf-8")

    assert '<html lang="en">' in content
    assert '<meta name="viewport"' in content
    assert 'role="main"' in content
    assert 'aria-label=' in content
    assert 'Skip to main content' in content
    # No remote scripts or CDN trackers
    assert "googleapis.com" not in content
    assert "cdn." not in content
    assert "unpkg.com" not in content


def test_api_client_routes_contract():
    """
    Verifies that frontend API client methods match registered backend FastAPI routes.
    Prevents URL drift between frontend and backend.
    """
    api_js_content = (FRONTEND_DIR / "js" / "api.js").read_text(encoding="utf-8")

    required_endpoints = [
        "/api/health",
        "/api/assessments",
        "/api/firmware/analyze",
        "/api/devices/ports",
        "/api/devices/identify",
        "/api/devices",
    ]
    for endpoint in required_endpoints:
        assert endpoint in api_js_content, f"API client missing endpoint {endpoint}"


def test_end_to_end_assessment_workflow_for_frontend(client: TestClient):
    """
    Simulates complete lifecycle invoked by frontend components:
    1. Upload firmware (Analyze component)
    2. Fetch assessment in overview / history
    3. Retrieve assessment detail and findings
    4. Download HTML and PDF reports
    5. Clean up via Delete endpoint
    """
    # 1. Analyze firmware
    bin_data = create_synthetic_esp32_binary()
    upload_res = client.post(
        "/api/firmware/analyze",
        files={"file": ("frontend_e2e_test.bin", io.BytesIO(bin_data), "application/octet-stream")},
    )
    assert upload_res.status_code == 200
    res_data = upload_res.json()
    assessment_id = res_data["assessment_id"]

    # 2. History & Overview list
    list_res = client.get("/api/assessments?skip=0&limit=10")
    assert list_res.status_code == 200
    assessments = list_res.json()["assessments"]
    matching = [a for a in assessments if a["id"] == assessment_id]
    assert len(matching) == 1

    # 3. Assessment Detail
    detail_res = client.get(f"/api/assessments/{assessment_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == assessment_id

    # 4. Report Downloads
    html_res = client.get(f"/api/assessments/{assessment_id}/report/html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]

    pdf_res = client.get(f"/api/assessments/{assessment_id}/report/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # 5. Delete Assessment
    del_res = client.delete(f"/api/assessments/{assessment_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    # 6. Verify 404 after deletion
    assert client.get(f"/api/assessments/{assessment_id}").status_code == 404
