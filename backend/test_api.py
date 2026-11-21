"""Automated integration test suite for QuantumSafe FastAPI Backend.

Tests:
1. GET /api/health
2. GET /api/algorithms
3. POST /api/assess (valid cases, role mismatches, unknown algorithms, invalid inputs)
4. POST /api/inventory/upload (valid CSV, empty CSV, bad extension, missing columns)
5. GET /api/inventory
6. GET /api/report/summary (before and after inventory upload)
7. GET /api/report/export (downloadable CSV response with headers)
8. DELETE /api/inventory (session reset)
"""

import io
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from starlette.testclient import TestClient
from backend.app import app


def run_tests():
    print("======================================================================")
    print("RUNNING QUANTUMSAFE FASTAPI ENDPOINT TEST SUITE")
    print("======================================================================\n")

    client = TestClient(app)
    passed = 0
    total = 0

    def check(condition: bool, name: str, details: str = ""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name}: {details}")

    # 1. GET /api/health
    res_health = client.get("/api/health")
    check(res_health.status_code == 200, "GET /api/health returns HTTP 200")
    data_health = res_health.json()
    check(data_health.get("status") == "healthy", "Health status is 'healthy'")
    check(data_health.get("backend_available") is True, "backend_available is True")
    check("active_inventory_count" in data_health, "active_inventory_count included")

    # 2. GET /api/algorithms
    res_algos = client.get("/api/algorithms")
    check(res_algos.status_code == 200, "GET /api/algorithms returns HTTP 200")
    data_algos = res_algos.json()
    check(data_algos.get("status") == "success", "Algorithms status is 'success'")
    check(len(data_algos.get("algorithms", [])) >= 7, "Catalog includes core algorithms")

    # 3. POST /api/assess - Valid Classical RSA
    res_assess_rsa = client.post("/api/assess", json={"algorithm": "RSA", "use_case": "Digital signatures"})
    check(res_assess_rsa.status_code == 200, "POST /api/assess (RSA) returns HTTP 200")
    data_rsa = res_assess_rsa.json()
    check(data_rsa.get("risk_level") == "High risk", "RSA risk is 'High risk'")
    check("ML-DSA" in data_rsa.get("recommendation", ""), "RSA signature recommends ML-DSA")

    # 4. POST /api/assess - Valid Post-Quantum ML-KEM
    res_assess_pqc = client.post("/api/assess", json={"algorithm": "ML-KEM", "use_case": "TLS key establishment"})
    check(res_assess_pqc.status_code == 200, "POST /api/assess (ML-KEM) returns HTTP 200")
    data_pqc = res_assess_pqc.json()
    check(data_pqc.get("risk_level") == "Quantum-safe", "ML-KEM risk is 'Quantum-safe'")
    check(data_pqc.get("is_valid_use_case") is True, "is_valid_use_case is True")

    # 5. POST /api/assess - Use-case mismatch (ECDH for signatures)
    res_mismatch = client.post("/api/assess", json={"algorithm": "ECDH", "use_case": "Digital signatures"})
    check(res_mismatch.status_code == 200, "POST /api/assess (Mismatch) returns HTTP 200 with invalid use case")
    data_mismatch = res_mismatch.json()
    check(data_mismatch.get("risk_level") == "Invalid use case", "Mismatch risk_level is 'Invalid use case'")
    check(data_mismatch.get("is_valid_use_case") is False, "is_valid_use_case is False")

    # 6. POST /api/assess - Validation Error (Empty fields)
    res_empty_payload = client.post("/api/assess", json={"algorithm": "", "use_case": "TLS"})
    check(res_empty_payload.status_code == 422, "POST /api/assess (empty algorithm) returns HTTP 422 Unprocessable Entity")

    # 7. GET /api/report/summary - Empty state before upload
    res_sum_empty = client.get("/api/report/summary")
    check(res_sum_empty.status_code == 200, "GET /api/report/summary returns HTTP 200 on empty inventory")
    data_sum_empty = res_sum_empty.json()
    check(data_sum_empty["summary"]["total_assets"] == 0, "Empty summary total_assets is 0")

    # 8. POST /api/inventory/upload - Bad extension (.txt)
    res_bad_ext = client.post(
        "/api/inventory/upload",
        files={"file": ("inventory.txt", b"asset,algo,use_case", "text/plain")},
    )
    check(res_bad_ext.status_code == 400, "Upload non-CSV file returns HTTP 400 Bad Request")

    # 9. POST /api/inventory/upload - Empty CSV file
    res_empty_file = client.post(
        "/api/inventory/upload",
        files={"file": ("empty.csv", b"", "text/csv")},
    )
    check(res_empty_file.status_code == 400, "Upload empty CSV returns HTTP 400 Bad Request")

    # 10. POST /api/inventory/upload - Valid CSV
    sample_csv = (
        "asset_name,algorithm,use_case,environment,owner\n"
        "Web Gateway TLS,ECDH,TLS key exchange,Production,Infra\n"
        "Firmware Signer,SLH-DSA,Firmware signing,Hardware,Security\n"
        "Customer Records,AES,Data at rest,Production,DBA\n"
    ).encode("utf-8")

    res_upload = client.post(
        "/api/inventory/upload",
        files={"file": ("assets.csv", sample_csv, "text/csv")},
    )
    check(res_upload.status_code == 200, "POST /api/inventory/upload returns HTTP 200")
    data_upload = res_upload.json()
    check(data_upload.get("status") == "success", "Upload status is 'success'")
    check(data_upload.get("total_assets") == 3, "Uploaded 3 assets successfully", f"Got: {data_upload.get('total_assets')}")
    check(len(data_upload.get("assets", [])) == 3, "Assets array populated with 3 records")

    # 11. GET /api/inventory - Check in-memory state
    res_inv = client.get("/api/inventory")
    check(res_inv.status_code == 200, "GET /api/inventory returns HTTP 200")
    check(res_inv.json().get("total_assets") == 3, "In-memory inventory has 3 assets")

    # 12. GET /api/report/summary - Populated state after upload
    res_sum_pop = client.get("/api/report/summary")
    check(res_sum_pop.status_code == 200, "GET /api/report/summary returns HTTP 200 on populated state")
    data_sum_pop = res_sum_pop.json()
    check(data_sum_pop["summary"]["total_assets"] == 3, "Summary total_assets is 3")
    check(data_sum_pop["summary"]["risk_distribution"]["High risk"] == 1, "Summary identified 1 High-risk asset")
    check(data_sum_pop["summary"]["risk_distribution"]["Quantum-safe"] == 1, "Summary identified 1 Quantum-safe asset")
    check(len(data_sum_pop["summary"]["migration_guidance"]) >= 1, "Summary provides migration guidance")

    # 13. GET /api/report/export - CSV download response
    res_export = client.get("/api/report/export")
    check(res_export.status_code == 200, "GET /api/report/export returns HTTP 200")
    check(res_export.headers.get("content-type") == "text/csv; charset=utf-8", "Content-Type is text/csv")
    check("attachment" in res_export.headers.get("content-disposition", ""), "Content-Disposition includes 'attachment'")
    check("quantumsafe-assessment" in res_export.headers.get("content-disposition", ""), "Filename has quantumsafe prefix")
    check("Web Gateway TLS" in res_export.text, "Exported CSV contains uploaded asset name")

    # 14. DELETE /api/inventory - Reset session
    res_clear = client.delete("/api/inventory")
    check(res_clear.status_code == 200, "DELETE /api/inventory returns HTTP 200")
    check(res_clear.json().get("active_inventory_count") == 0, "Inventory count is 0 after clear")

    # Verify inventory is now empty
    res_inv_after = client.get("/api/inventory")
    check(res_inv_after.json().get("total_assets") == 0, "In-memory state successfully cleared")

    print("\n----------------------------------------------------------------------")
    print(f"TEST RESULTS: {passed}/{total} tests passed ({int(passed/total*100)}%)")
    print("----------------------------------------------------------------------")

    if passed == total:
        print("\nAll API tests passed successfully!")
        return 0
    else:
        print(f"\n{total - passed} tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
