"""Automated test suite for QuantumSafe Report Generation Module.

Tests:
1. Normal report generation
2. Empty results handling
3. Missing fields and fallback resolution
4. Special characters (quotes, commas, newlines in data fields)
5. Multiple assets with diverse risk profiles
6. Correct summary metric calculations
7. Safe filename generation and sanitization
"""

import csv
import io
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.report import (
    STANDARD_REPORT_HEADERS,
    calculate_report_summary,
    create_csv_report,
    get_safe_report_filename,
    sanitize_filename,
)


def run_tests():
    print("======================================================================")
    print("RUNNING QUANTUMSAFE REPORT GENERATION TEST SUITE")
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

    # Sample assessment data
    sample_records = [
        {
            "asset_name": "API Gateway TLS",
            "algorithm": "ECDH",
            "use_case": "TLS key exchange",
            "risk_level": "High risk",
            "prioritization_score": 95,
            "reason": "Vulnerable to Shor's algorithm.",
            "quantum_threat": "Shor's algorithm breaks ECDLP.",
            "recommendation": "Migrate to ML-KEM (NIST FIPS 203).",
            "reference_citation": "NIST FIPS 203",
            "environment": "Production",
            "owner": "Security Engineering",
            "criticality": "Critical",
        },
        {
            "asset_name": "Document Signer",
            "algorithm": "RSA",
            "use_case": "Digital signatures",
            "risk_level": "High risk",
            "prioritization_score": 90,
            "reason": "Integer factorization solvable by Shor's algorithm.",
            "quantum_threat": "Forged signatures.",
            "recommendation": "Migrate to ML-DSA (NIST FIPS 204).",
            "reference_citation": "NIST FIPS 204",
            "environment": "Production",
            "owner": "Legal",
            "criticality": "High",
        },
        {
            "asset_name": "Customer DB Encrypted Volume",
            "algorithm": "AES",
            "use_case": "Data at rest",
            "risk_level": "Lower quantum risk",
            "prioritization_score": 30,
            "reason": "Grover's algorithm provides quadratic speedup.",
            "quantum_threat": "Key search halved.",
            "recommendation": "Deploy AES-256.",
            "reference_citation": "NIST SP 800-57",
            "environment": "Production",
            "owner": "DBA",
            "criticality": "Critical",
        },
        {
            "asset_name": "Next-Gen Key Escrow",
            "algorithm": "ML-KEM",
            "use_case": "TLS key establishment",
            "risk_level": "Quantum-safe",
            "prioritization_score": 10,
            "reason": "Lattice-based security resisting quantum attacks.",
            "quantum_threat": "No known practical quantum attack.",
            "recommendation": "No replacement required; deploy ML-KEM-768.",
            "reference_citation": "NIST FIPS 203",
            "environment": "Staging",
            "owner": "Platform",
            "criticality": "Medium",
        },
    ]

    # 1. Normal Report Generation
    csv_out = create_csv_report(sample_records)
    check(bool(csv_out), "CSV report generated non-empty string")

    # Parse back using standard csv module to verify RFC-4180 validity
    reader = csv.reader(io.StringIO(csv_out))
    rows = list(reader)
    check(len(rows) == 5, "Generated 1 header row + 4 data rows (5 total)", f"Row count: {len(rows)}")
    check(rows[0] == STANDARD_REPORT_HEADERS, "Header columns match STANDARD_REPORT_HEADERS")
    check(rows[1][0] == "API Gateway TLS", "First row asset_name parsed correctly")
    check(rows[1][1] == "ECDH", "First row algorithm matches")
    check(rows[1][3] == "High risk", "First row risk_level matches")
    check("ML-KEM" in rows[1][7], "First row recommendation matches")

    # 2. Empty Results Handling
    empty_csv = create_csv_report([])
    empty_rows = list(csv.reader(io.StringIO(empty_csv)))
    check(len(empty_rows) == 1, "Empty records input returns header row only")
    check(empty_rows[0] == STANDARD_REPORT_HEADERS, "Empty records preserves valid CSV header")

    # 3. Missing Fields and Frontend Aliases
    alias_records = [
        {
            "asset": "Legacy Server",
            "algo": "RSA",
            "useCase": "Certificate authentication",
            "risk": "High risk",
            "alternative": "ML-DSA (FIPS 204)",
            # Environment, owner, criticality missing
        }
    ]
    alias_csv = create_csv_report(alias_records)
    alias_parsed = list(csv.reader(io.StringIO(alias_csv)))
    check(len(alias_parsed) == 2, "Alias records parsed into 2 rows")
    check(alias_parsed[1][0] == "Legacy Server", "Fallback key 'asset' resolved correctly")
    check(alias_parsed[1][1] == "RSA", "Fallback key 'algo' resolved correctly")
    check(alias_parsed[1][9] == "Production", "Missing environment defaulted to 'Production'")
    check(alias_parsed[1][10] == "Unspecified", "Missing owner defaulted to 'Unspecified'")

    # 4. Special Characters (Quotes, Commas, Newlines in data)
    tricky_records = [
        {
            "asset_name": 'Server "Alpha", Primary',
            "algorithm": "ECDSA",
            "use_case": "Digital signatures, external",
            "risk_level": "High risk",
            "prioritization_score": 90,
            "reason": "Line 1.\nLine 2 with comma, and quotes: 'test'.",
            "quantum_threat": 'Threat with "embedded quotes"',
            "recommendation": "Use ML-DSA (NIST FIPS 204); or SLH-DSA.",
            "reference_citation": "NIST FIPS 204",
        }
    ]
    tricky_csv = create_csv_report(tricky_records)
    tricky_parsed = list(csv.reader(io.StringIO(tricky_csv)))
    check(len(tricky_parsed) == 2, "Tricky characters handled without breaking row structure")
    check(tricky_parsed[1][0] == 'Server "Alpha", Primary', "Quotes and commas in asset name preserved exactly")
    check("\n" in tricky_parsed[1][5], "Embedded newline in explanation parsed cleanly")

    # 5. Summary Calculations
    summary = calculate_report_summary(sample_records)
    check(summary["total_assets"] == 4, "Summary total_assets is 4", f"Got: {summary['total_assets']}")
    check(summary["risk_distribution"]["High risk"] == 2, "Summary High risk count is 2")
    check(summary["risk_distribution"]["Lower quantum risk"] == 1, "Summary Lower quantum risk count is 1")
    check(summary["risk_distribution"]["Quantum-safe"] == 1, "Summary Quantum-safe count is 1")
    check(summary["risk_percentages"]["High risk"] == 50.0, "High risk percentage is 50.0%")
    check(summary["algorithm_distribution"]["ECDH"] == 1, "Algorithm distribution tracks ECDH count")
    check(summary["algorithm_distribution"]["AES"] == 1, "Algorithm distribution tracks AES count")
    check(summary["recommendations_count"] == 3, "Recommendations count correctly excludes 'no replacement required' (3)")
    check(len(summary["migration_guidance"]) >= 2, "Contextual migration guidance generated")
    check(any("Shor" in g for g in summary["migration_guidance"]), "Guidance specifically addresses high-risk Shor exposure")

    # 6. Summary for Empty List
    empty_summary = calculate_report_summary([])
    check(empty_summary["total_assets"] == 0, "Empty list summary total_assets is 0")
    check(empty_summary["average_prioritization_score"] == 0.0, "Empty list avg score is 0.0")
    check(len(empty_summary["migration_guidance"]) == 1, "Empty list provides prompt to upload CSV")

    # 7. Safe Filename Generation
    safe_name = get_safe_report_filename("client-audit/../../test")
    check("/" not in safe_name and "\\" not in safe_name, "Filename sanitized against path traversal")
    check(safe_name.endswith(".csv"), "Filename ends in .csv")
    check("client_audit" in safe_name or "test" in safe_name, "Filename contains sanitized prefix")

    print("\n----------------------------------------------------------------------")
    print(f"TEST RESULTS: {passed}/{total} tests passed ({int(passed/total*100)}%)")
    print("----------------------------------------------------------------------")

    if passed == total:
        print("\nAll report tests passed successfully!")
        return 0
    else:
        print(f"\n{total - passed} tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
