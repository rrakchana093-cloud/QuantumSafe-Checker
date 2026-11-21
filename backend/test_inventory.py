"""Automated test suite for QuantumSafe Asset Inventory Module.

Tests:
1. Valid CSV parsing and assessment
2. Empty CSV
3. Missing required columns
4. Duplicate records handling
5. Invalid algorithms
6. Invalid use cases
7. Malformed rows
8. Missing values within rows
9. Optional fields support
10. UTF-8 BOM encoding handling
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.inventory import (
    parse_and_validate_csv,
    process_inventory_csv,
    validate_file_metadata,
)
from backend.security_rules import RISK_HIGH, RISK_INVALID, RISK_LOWER, RISK_SAFE, RISK_UNKNOWN


def run_tests():
    print("======================================================================")
    print("RUNNING QUANTUMSAFE INVENTORY MODULE TEST SUITE")
    print("======================================================================\n")

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

    # 1. Valid CSV Test
    valid_csv = """asset_name,algorithm,use_case,environment,owner
Payment Gateway TLS,ECDH,TLS key exchange,Production,Security Team
Database Storage Encryption,AES,Data at rest,Production,DBA Team
Firmware Signing Key,SLH-DSA,Firmware signing,Hardware,Embedded Eng
API Gateway Service,ML-KEM,TLS key establishment,Staging,DevOps
Legacy Auth Token,RSA,Digital signatures,Legacy,Identity Team
"""
    res_valid = process_inventory_csv(valid_csv, filename="assets.csv")
    check(res_valid["status"] == "success", "Valid CSV processes with status 'success'")
    check(res_valid["total_assets"] == 5, "Total assets counted correctly (5)", f"Count: {res_valid['total_assets']}")
    check(res_valid["summary"]["high_risk"] == 2, "Identified 2 high-risk assets (ECDH, RSA)", f"Got: {res_valid['summary']['high_risk']}")
    check(res_valid["summary"]["lower_risk"] == 1, "Identified 1 lower-risk asset (AES)", f"Got: {res_valid['summary']['lower_risk']}")
    check(res_valid["summary"]["quantum_safe"] == 2, "Identified 2 quantum-safe assets (SLH-DSA, ML-KEM)", f"Got: {res_valid['summary']['quantum_safe']}")
    check(res_valid["assets"][0]["environment"] == "Production", "Optional environment preserved")
    check(res_valid["assets"][0]["owner"] == "Security Team", "Optional owner preserved")
    # Verify frontend compatibility keys exist
    check("asset" in res_valid["assets"][0] and "useCase" in res_valid["assets"][0], "Frontend camelCase aliases present")

    # 2. Empty CSV Test
    res_empty = process_inventory_csv("", filename="empty.csv")
    check(res_empty["status"] == "error", "Empty CSV fails gracefully with status 'error'")
    check("empty" in res_empty["message"].lower(), "Empty CSV error message informative")

    # 3. Missing Required Columns Test
    missing_col_csv = """asset_name,use_case
Web Server,TLS key exchange
"""
    res_missing = process_inventory_csv(missing_col_csv, filename="bad_cols.csv")
    check(res_missing["status"] == "error", "Missing column 'algorithm' causes error status")
    check(any("algorithm" in err.lower() for err in res_missing["errors"]), "Error message specifies missing 'algorithm'")

    # 4. Duplicate Records Test
    dup_csv = """asset_name,algorithm,use_case
Service Bus,RSA,Digital signatures
Service Bus,RSA,Digital signatures
"""
    records, errors, warnings = parse_and_validate_csv(dup_csv)
    check(len(records) == 2, "Duplicates are parsed")
    check(len(warnings) >= 1, "Duplicate asset definition generates a warning")
    check("Duplicate" in warnings[0], "Warning specifically mentions duplicate")

    # 5. Invalid / Unknown Algorithm in CSV
    unknown_algo_csv = """asset_name,algorithm,use_case
Quantum Portal,SuperAlienCipher,TLS key exchange
"""
    res_unknown = process_inventory_csv(unknown_algo_csv, filename="unknown.csv")
    check(res_unknown["status"] == "success", "Unknown algorithm processes without crashing")
    check(res_unknown["assets"][0]["risk_level"] == RISK_UNKNOWN, "Unknown algorithm risk is RISK_UNKNOWN")

    # 6. Invalid Use Case Mismatch
    mismatch_csv = """asset_name,algorithm,use_case
Corporate VPN,ECDH,Digital signatures
"""
    res_mismatch = process_inventory_csv(mismatch_csv, filename="mismatch.csv")
    check(res_mismatch["status"] == "success", "Mismatch processes cleanly")
    check(res_mismatch["assets"][0]["risk_level"] == RISK_INVALID, "ECDH for signatures flagged as Invalid use case")
    check(not res_mismatch["assets"][0]["is_valid_use_case"], "is_valid_use_case set to False")
    check("ML-DSA" in res_mismatch["assets"][0]["recommendation"], "Mismatched signature recommends signature standard (ML-DSA)")

    # 7. Malformed Row Test (Uneven column counts)
    malformed_csv = """asset_name,algorithm,use_case
Valid Asset 1,RSA,Digital signatures
Malformed Row with only two columns,RSA
Valid Asset 2,AES,Data at rest
"""
    res_malformed = process_inventory_csv(malformed_csv, filename="malformed.csv")
    check(res_malformed["status"] == "partial_success", "Malformed row results in partial_success status")
    check(res_malformed["total_assets"] == 2, "Only valid rows are imported (2)")
    check(len(res_malformed["errors"]) >= 1, "Malformed row reported in errors list")

    # 8. Missing Values within Row
    blank_cell_csv = """asset_name,algorithm,use_case
,RSA,Digital signatures
Server 2,,TLS key exchange
Server 3,AES,
Server 4,ML-KEM,TLS key establishment
"""
    res_blanks = process_inventory_csv(blank_cell_csv, filename="blanks.csv")
    check(res_blanks["total_assets"] == 1, "Only row with all required values imported (1)")
    check(len(res_blanks["errors"]) == 3, "All 3 blank-field rows captured in errors list")

    # 9. UTF-8 with BOM Test (Common Excel export)
    bom_csv = "\ufeffasset_name,algorithm,use_case\nSecure Vault,AES,Data at rest\n".encode("utf-8")
    res_bom = process_inventory_csv(bom_csv, filename="excel_export.csv")
    check(res_bom["status"] == "success", "UTF-8 with BOM decoded cleanly")
    check(res_bom["assets"][0]["asset_name"] == "Secure Vault", "Asset name matches without BOM corruption")

    # 10. File Metadata Validation (Extension & Size Limits)
    valid_ext, _ = validate_file_metadata("test.csv", 100)
    check(valid_ext, "Valid .csv extension accepted")

    invalid_ext, err_ext = validate_file_metadata("malware.exe", 100)
    check(not invalid_ext, "Non-csv file rejected (.exe)")
    check(".csv" in err_ext, "Error specifies only .csv supported")

    oversize, err_size = validate_file_metadata("huge.csv", 10 * 1024 * 1024, max_size_bytes=5 * 1024 * 1024)
    check(not oversize, "File exceeding size limit rejected")

    print("\n----------------------------------------------------------------------")
    print(f"TEST RESULTS: {passed}/{total} tests passed ({int(passed/total*100)}%)")
    print("----------------------------------------------------------------------")

    if passed == total:
        print("\nAll inventory tests passed successfully!")
        return 0
    else:
        print(f"\n{total - passed} tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
