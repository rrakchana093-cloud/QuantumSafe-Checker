"""
QuantumSafe - Comprehensive Live QA Test Suite
Step 9: Complete Application QA & Verification

Tests live running frontend (http://localhost:8443) and live backend (http://127.0.0.1:8000),
including Vite reverse proxy, API endpoints, integration workflows, error conditions,
and cryptographic accuracy.
"""

import urllib.request
import urllib.error
import json
import uuid
import sys
import os

BACKEND_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://localhost:8443"

test_results = []

def run_test(test_id, category, description, fn):
    print(f"\n--- [{test_id}] {category}: {description} ---")
    try:
        fn()
        print(f"[PASS] {test_id} - {description}")
        test_results.append({
            "id": test_id,
            "category": category,
            "description": description,
            "status": "PASS",
            "error": None
        })
    except Exception as e:
        print(f"[FAIL] {test_id} - {description}: {str(e)}")
        test_results.append({
            "id": test_id,
            "category": category,
            "description": description,
            "status": "FAIL",
            "error": str(e)
        })

# Helper for HTTP requests
def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "QuantumSafe-QA/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8")

def http_post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "QuantumSafe-QA/1.0"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8")

def http_delete(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "QuantumSafe-QA/1.0"},
        method="DELETE"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8")

def http_post_multipart(url, filename, content_bytes, content_type="text/csv"):
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
    body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
    body.extend(content_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(
        url,
        data=bytes(body),
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "QuantumSafe-QA/1.0"
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8")


# ==============================================================================
# SECTION A: FRONTEND TESTING
# ==============================================================================

def test_frontend_dev_server():
    status, headers, body = http_get(FRONTEND_URL)
    assert status == 200, f"Expected 200, got {status}"
    assert "<div id=\"root\">" in body, "Missing root div in index.html"
    assert "QuantumSafe" in body or "vite" in body.lower(), "Page content missing expected elements"

def test_frontend_vite_proxy():
    status, headers, body = http_get(f"{FRONTEND_URL}/api/health")
    assert status == 200, f"Expected 200, got {status}"
    data = json.loads(body)
    assert data.get("status") == "healthy", f"Unexpected proxy health response: {data}"

def test_frontend_production_build_artifacts():
    dist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
    assert os.path.exists(dist_dir), "dist/ directory does not exist. Run npm run build."
    index_html = os.path.join(dist_dir, "index.html")
    assert os.path.exists(index_html), "dist/index.html missing"
    assets_dir = os.path.join(dist_dir, "assets")
    assert os.path.exists(assets_dir), "dist/assets missing"
    assets = os.listdir(assets_dir)
    js_files = [f for f in assets if f.endswith(".js")]
    css_files = [f for f in assets if f.endswith(".css")]
    assert len(js_files) > 0, "No JS bundle in dist/assets"
    assert len(css_files) > 0, "No CSS bundle in dist/assets"


# ==============================================================================
# SECTION B: BACKEND TESTING
# ==============================================================================

def test_backend_health():
    status, headers, body = http_get(f"{BACKEND_URL}/api/health")
    assert status == 200
    data = json.loads(body)
    assert data.get("status") == "healthy"
    assert data.get("backend_available") is True
    assert "version" in data

def test_backend_algorithms_catalog():
    status, headers, body = http_get(f"{BACKEND_URL}/api/algorithms")
    assert status == 200
    data = json.loads(body)
    assert data.get("status") == "success"
    algos = data.get("algorithms", [])
    assert len(algos) >= 7, f"Expected at least 7 algorithms, got {len(algos)}"
    names = [a.get("name") for a in algos]
    for required in ["RSA", "ECDH", "ECDSA", "AES", "ML-KEM", "ML-DSA", "SLH-DSA"]:
        assert required in names, f"Missing required algorithm: {required}"

def test_backend_assess_post():
    status, headers, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "ML-KEM", "use_case": "TLS key exchange"}
    )
    assert status == 200
    data = json.loads(body)
    assert data.get("algorithm") == "ML-KEM"
    assert data.get("risk_level") == "Quantum-safe"
    assert data.get("is_valid_use_case") is True

def test_backend_inventory_empty_state():
    # Clear first
    http_delete(f"{BACKEND_URL}/api/inventory")
    status, headers, body = http_get(f"{BACKEND_URL}/api/report/summary")
    assert status == 200
    data = json.loads(body)
    assert data.get("total_assets") == 0
    assert data.get("risk_breakdown", {}).get("High risk") == 0


# ==============================================================================
# SECTION C: INTEGRATION WORKFLOW TESTING
# ==============================================================================

def test_integration_rsa_assessment():
    status, headers, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "RSA", "use_case": "Digital signatures"}
    )
    assert status == 200
    data = json.loads(body)
    assert data["risk_level"] == "High risk"
    assert "Shor" in data["risk_explanation"] or "shor" in data["risk_explanation"].lower()
    assert "ML-DSA" in data["recommendation"] or "SLH-DSA" in data["recommendation"]

def test_integration_aes_assessment():
    status, headers, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "AES", "use_case": "Data encryption"}
    )
    assert status == 200
    data = json.loads(body)
    assert data["risk_level"] == "Lower quantum risk"
    assert "Grover" in data["risk_explanation"] or "grover" in data["risk_explanation"].lower()
    assert "AES-256" in data["recommendation"]

def test_integration_csv_upload_and_inventory():
    csv_content = (
        "asset_name,algorithm,use_case,environment,owner\n"
        "Payments Gateway TLS,ECDH,TLS key exchange,Production,SecOps\n"
        "Root CA Certificate,RSA,Digital signatures,Production,PKI Team\n"
        "Customer DB At-Rest,AES,Data encryption,Production,Database Team\n"
        "Firmware Signing Key,SLH-DSA,Firmware signing,Production,Embedded Sec\n"
        "Future API Key Exchange,ML-KEM,TLS key exchange,Staging,DevOps\n"
    ).encode("utf-8")

    status, headers, body = http_post_multipart(
        f"{BACKEND_URL}/api/inventory/upload",
        "qa_assets.csv",
        csv_content
    )
    assert status == 200
    data = json.loads(body)
    assert data.get("status") == "success"
    assert data.get("total_assets") == 5
    assert len(data.get("assets", [])) == 5

    # Verify inventory state
    status, headers, body = http_get(f"{BACKEND_URL}/api/inventory")
    assert status == 200
    inv = json.loads(body)
    assert inv.get("total_assets") == 5

def test_integration_report_summary():
    status, headers, body = http_get(f"{BACKEND_URL}/api/report/summary")
    assert status == 200
    summary = json.loads(body)
    assert summary["total_assets"] == 5
    assert summary["risk_breakdown"]["High risk"] == 2
    assert summary["risk_breakdown"]["Lower quantum risk"] == 1
    assert summary["risk_breakdown"]["Quantum-safe"] == 2
    assert summary["high_risk_percentage"] == 40.0
    assert summary["requires_replacement_count"] == 3

def test_integration_report_download():
    status, headers, body = http_get(f"{BACKEND_URL}/api/report/export")
    assert status == 200
    content_type = headers.get("Content-Type", "")
    assert "text/csv" in content_type
    content_disp = headers.get("Content-Disposition", "")
    assert "attachment" in content_disp
    assert "filename=" in content_disp
    assert "asset_name" in body
    assert "Payments Gateway TLS" in body
    assert "Firmware Signing Key" in body


# ==============================================================================
# SECTION D: ERROR TESTING
# ==============================================================================

def test_error_unknown_algorithm():
    status, headers, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "QuantumX-9000", "use_case": "Digital signatures"}
    )
    assert status == 200
    data = json.loads(body)
    assert data["risk_level"] in ["Unknown", "High risk"]
    assert data["is_valid_use_case"] is False

def test_error_use_case_mismatch_ecdh_signatures():
    status, headers, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "ECDH", "use_case": "Digital signatures"}
    )
    assert status == 200
    data = json.loads(body)
    assert data["risk_level"] == "Invalid use case"
    assert data["is_valid_use_case"] is False
    assert "ML-DSA" in data["recommendation"]

def test_error_invalid_assess_body_missing_fields():
    try:
        http_post_json(f"{BACKEND_URL}/api/assess", {"algorithm": ""})
        assert False, "Expected HTTP 422"
    except urllib.error.HTTPError as e:
        assert e.code == 422, f"Expected HTTP 422, got {e.code}"

def test_error_upload_invalid_extension():
    try:
        http_post_multipart(
            f"{BACKEND_URL}/api/inventory/upload",
            "malicious.exe",
            b"BINARY_EXEC_CONTENT",
            content_type="application/octet-stream"
        )
        assert False, "Expected HTTP 400"
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"Expected HTTP 400, got {e.code}"
        err_body = e.read().decode("utf-8")
        assert "csv" in err_body.lower()

def test_error_upload_empty_file():
    try:
        http_post_multipart(
            f"{BACKEND_URL}/api/inventory/upload",
            "empty.csv",
            b"",
            content_type="text/csv"
        )
        assert False, "Expected HTTP 400"
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"Expected HTTP 400, got {e.code}"

def test_error_upload_missing_required_columns():
    bad_csv = "service_name,owner\nServiceA,Alice\n".encode("utf-8")
    try:
        http_post_multipart(
            f"{BACKEND_URL}/api/inventory/upload",
            "missing_cols.csv",
            bad_csv,
            content_type="text/csv"
        )
        assert False, "Expected HTTP 400"
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"Expected HTTP 400, got {e.code}"
        err_body = e.read().decode("utf-8")
        assert "algorithm" in err_body.lower() or "missing" in err_body.lower()


# ==============================================================================
# SECTION E: CRYPTOGRAPHIC ACCURACY VERIFICATION
# ==============================================================================

def test_crypto_shor_algorithm_explanation():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "RSA", "use_case": "Digital signatures"}
    )
    data = json.loads(body)
    explanation = data["risk_explanation"]
    assert "Shor" in explanation
    assert "factor" in explanation.lower() or "polynomial" in explanation.lower()

def test_crypto_ecc_discrete_log_explanation():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "ECDSA", "use_case": "Digital signatures"}
    )
    data = json.loads(body)
    explanation = data["risk_explanation"]
    assert "discrete logarithm" in explanation.lower() or "shor" in explanation.lower()

def test_crypto_grover_algorithm_explanation():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "AES", "use_case": "Data encryption"}
    )
    data = json.loads(body)
    explanation = data["risk_explanation"]
    assert "Grover" in explanation
    assert "quadratic" in explanation.lower() or "halv" in explanation.lower() or "128" in explanation

def test_crypto_ml_kem_fips_203():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "ML-KEM", "use_case": "TLS key exchange"}
    )
    data = json.loads(body)
    explanation = data["risk_explanation"]
    assert "FIPS 203" in explanation
    assert data["risk_level"] == "Quantum-safe"

def test_crypto_ml_dsa_fips_204():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "ML-DSA", "use_case": "Digital signatures"}
    )
    data = json.loads(body)
    explanation = data["risk_explanation"]
    assert "FIPS 204" in explanation
    assert data["risk_level"] == "Quantum-safe"

def test_crypto_slh_dsa_fips_205():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "SLH-DSA", "use_case": "Digital signatures"}
    )
    data = json.loads(body)
    explanation = data["risk_explanation"]
    assert "FIPS 205" in explanation
    assert data["risk_level"] == "Quantum-safe"

def test_crypto_legacy_names_kyber_dilithium():
    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "Kyber", "use_case": "TLS key exchange"}
    )
    data = json.loads(body)
    assert "ML-KEM" in data["recommendation"] or "standardized" in data["risk_explanation"]

    status, _, body = http_post_json(
        f"{BACKEND_URL}/api/assess",
        {"algorithm": "Dilithium", "use_case": "Digital signatures"}
    )
    data = json.loads(body)
    assert "ML-DSA" in data["recommendation"] or "standardized" in data["risk_explanation"]


# ==============================================================================
# MAIN TEST EXECUTION
# ==============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("QUANTUMSAFE LIVE FULL-STACK QA TEST RUNNER")
    print("Testing live Frontend (Vite) and Backend (FastAPI)")
    print("=" * 80)

    # Section A
    run_test("QA-FE-01", "Frontend", "Vite Dev Server HTTP 200 & Root HTML", test_frontend_dev_server)
    run_test("QA-FE-02", "Frontend", "Vite Reverse Proxy Routing /api/health", test_frontend_vite_proxy)
    run_test("QA-FE-03", "Frontend", "Production Build Artifacts in dist/", test_frontend_production_build_artifacts)

    # Section B
    run_test("QA-BE-01", "Backend", "GET /api/health Endpoint Check", test_backend_health)
    run_test("QA-BE-02", "Backend", "GET /api/algorithms Catalog Check", test_backend_algorithms_catalog)
    run_test("QA-BE-03", "Backend", "POST /api/assess Baseline Check", test_backend_assess_post)
    run_test("QA-BE-04", "Backend", "GET /api/report/summary Empty State Check", test_backend_inventory_empty_state)

    # Section C
    run_test("QA-INT-01", "Integration", "RSA High Risk & Shor Assessment Workflow", test_integration_rsa_assessment)
    run_test("QA-INT-02", "Integration", "AES Lower Quantum Risk & Grover Workflow", test_integration_aes_assessment)
    run_test("QA-INT-03", "Integration", "CSV Asset Inventory Upload & Parsing", test_integration_csv_upload_and_inventory)
    run_test("QA-INT-04", "Integration", "Report Summary Aggregation & Real Metrics", test_integration_report_summary)
    run_test("QA-INT-05", "Integration", "CSV Report Download & Content Integrity", test_integration_report_download)

    # Section D
    run_test("QA-ERR-01", "Error Handling", "Graceful Handling of Unknown Algorithms", test_error_unknown_algorithm)
    run_test("QA-ERR-02", "Error Handling", "Use-Case Mismatch Flags Invalid Use Case", test_error_use_case_mismatch_ecdh_signatures)
    run_test("QA-ERR-03", "Error Handling", "Missing Payload Fields Returns HTTP 422", test_error_invalid_assess_body_missing_fields)
    run_test("QA-ERR-04", "Error Handling", "Non-CSV Upload Rejected with HTTP 400", test_error_upload_invalid_extension)
    run_test("QA-ERR-05", "Error Handling", "Empty File Upload Rejected with HTTP 400", test_error_upload_empty_file)
    run_test("QA-ERR-06", "Error Handling", "Missing Schema Columns Rejected with HTTP 400", test_error_upload_missing_required_columns)

    # Section E
    run_test("QA-CRY-01", "Cryptographic Accuracy", "Shor's Algorithm Factoring Verification", test_crypto_shor_algorithm_explanation)
    run_test("QA-CRY-02", "Cryptographic Accuracy", "ECC Discrete Logarithm Attack Verification", test_crypto_ecc_discrete_log_explanation)
    run_test("QA-CRY-03", "Cryptographic Accuracy", "Grover's Algorithm Quadratic Speedup Verification", test_crypto_grover_algorithm_explanation)
    run_test("QA-CRY-04", "Cryptographic Accuracy", "ML-KEM NIST FIPS 203 Standard Verification", test_crypto_ml_kem_fips_203)
    run_test("QA-CRY-05", "Cryptographic Accuracy", "ML-DSA NIST FIPS 204 Standard Verification", test_crypto_ml_dsa_fips_204)
    run_test("QA-CRY-06", "Cryptographic Accuracy", "SLH-DSA NIST FIPS 205 Standard Verification", test_crypto_slh_dsa_fips_205)
    run_test("QA-CRY-07", "Cryptographic Accuracy", "Legacy Predecessors (Kyber/Dilithium) Distinction", test_crypto_legacy_names_kyber_dilithium)

    # Summary
    total = len(test_results)
    passed = sum(1 for r in test_results if r["status"] == "PASS")
    failed = sum(1 for r in test_results if r["status"] == "FAIL")

    print("\n" + "=" * 80)
    print(f"LIVE QA EXECUTION COMPLETED: {passed}/{total} Passed ({passed/total*100:.1f}%), {failed} Failed")
    print("=" * 80)

    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)
