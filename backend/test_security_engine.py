"""Automated test suite for QuantumSafe Cryptographic Security Engine.

Tests:
1. Every supported algorithm (RSA, ECDH, ECDSA, AES, ML-KEM, ML-DSA, SLH-DSA)
2. Predecessor / legacy names (Kyber, Dilithium, Falcon)
3. Valid use cases
4. Invalid combinations (e.g. ECDH for signatures, ML-KEM for code signing)
5. Unknown algorithms
6. Missing inputs
7. Role-appropriate recommendations
8. NIST reference citations
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.security_rules import (
    RISK_HIGH,
    RISK_INVALID,
    RISK_LOWER,
    RISK_SAFE,
    RISK_UNKNOWN,
    assess_algorithm,
    find_algorithm,
    get_supported_algorithms,
)


def run_tests():
    print("======================================================================")
    print("RUNNING QUANTUMSAFE SECURITY ENGINE TEST SUITE")
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

    # 1. Database loading
    algorithms = get_supported_algorithms()
    check(len(algorithms) >= 10, "Database loaded at least 10 algorithm entries", f"Count: {len(algorithms)}")

    # 2. Test Classical: RSA for signatures and key exchange
    res_rsa_sig = assess_algorithm("RSA", "Digital signatures")
    check(res_rsa_sig["risk_level"] == RISK_HIGH, "RSA for Digital signatures is High risk")
    check("ML-DSA" in res_rsa_sig["recommendation"], "RSA signature recommendation mentions ML-DSA")
    check("Shor" in res_rsa_sig["quantum_threat"], "RSA mentions Shor's algorithm")

    res_rsa_ke = assess_algorithm("RSA", "TLS key exchange")
    check(res_rsa_ke["risk_level"] == RISK_HIGH, "RSA for TLS key exchange is High risk")
    check("ML-KEM" in res_rsa_ke["recommendation"], "RSA key exchange recommendation mentions ML-KEM")

    # 3. Test Classical: ECDH
    res_ecdh = assess_algorithm("ECDH", "TLS key exchange")
    check(res_ecdh["risk_level"] == RISK_HIGH, "ECDH for TLS key exchange is High risk")
    check("ML-KEM" in res_ecdh["recommendation"], "ECDH recommendation suggests ML-KEM")
    check("discrete logarithm" in res_ecdh["reason"].lower(), "ECDH mentions discrete logarithm")

    # 4. Test Classical: ECDSA
    res_ecdsa = assess_algorithm("ECDSA", "Code signing")
    check(res_ecdsa["risk_level"] == RISK_HIGH, "ECDSA for Code signing is High risk")
    check("ML-DSA" in res_ecdsa["recommendation"], "ECDSA recommendation suggests ML-DSA")

    # 5. Test Symmetric: AES
    res_aes = assess_algorithm("AES", "Data at rest")
    check(res_aes["risk_level"] == RISK_LOWER, "AES for Data at rest is Lower quantum risk")
    check("Grover" in res_aes["quantum_threat"], "AES mentions Grover's algorithm")
    check("AES-256" in res_aes["recommendation"], "AES recommends AES-256")

    # Test AES key size
    res_aes_128 = assess_algorithm("AES", "Data at rest", key_size=128)
    check(res_aes_128["risk_level"] == RISK_HIGH, "AES-128 is flagged as High risk due to 64-bit Grover quantum bound")

    res_aes_256 = assess_algorithm("AES", "Data at rest", key_size=256)
    check(res_aes_256["risk_level"] == RISK_LOWER, "AES-256 remains Lower quantum risk with 128-bit quantum security")

    # 6. Test Post-Quantum: ML-KEM (FIPS 203)
    res_mlkem = assess_algorithm("ML-KEM", "TLS key establishment")
    check(res_mlkem["risk_level"] == RISK_SAFE, "ML-KEM is Quantum-safe")
    check("FIPS 203" in res_mlkem["reference_citation"], "ML-KEM cites NIST FIPS 203")

    # 7. Test Post-Quantum: ML-DSA (FIPS 204)
    res_mldsa = assess_algorithm("ML-DSA", "Certificate authentication")
    check(res_mldsa["risk_level"] == RISK_SAFE, "ML-DSA is Quantum-safe")
    check("FIPS 204" in res_mldsa["reference_citation"], "ML-DSA cites NIST FIPS 204")

    # 8. Test Post-Quantum: SLH-DSA (FIPS 205)
    res_slhdsa = assess_algorithm("SLH-DSA", "Root-of-trust signing")
    check(res_slhdsa["risk_level"] == RISK_SAFE, "SLH-DSA is Quantum-safe")
    check("FIPS 205" in res_slhdsa["reference_citation"], "SLH-DSA cites NIST FIPS 205")

    # 9. Test Legacy Names: Kyber, Dilithium, Falcon
    res_kyber = assess_algorithm("Kyber", "TLS key establishment")
    check(res_kyber["standardization_status"] == "legacy_predecessor", "Kyber recognized as legacy predecessor")
    check("ML-KEM" in res_kyber["recommendation"], "Kyber recommends upgrading to standardized ML-KEM")

    res_dilithium = assess_algorithm("Dilithium", "Document signing")
    check(res_dilithium["standardization_status"] == "legacy_predecessor", "Dilithium recognized as legacy predecessor")
    check("ML-DSA" in res_dilithium["recommendation"], "Dilithium recommends upgrading to standardized ML-DSA")

    res_falcon = assess_algorithm("Falcon", "Code signing")
    check(res_falcon["standardization_status"] == "candidate_in_progress", "Falcon recognized as candidate in progress")
    check("FN-DSA" in res_falcon["recommendation"] or "ML-DSA" in res_falcon["recommendation"], "Falcon recommendation provides realistic migration advice")

    # 10. Test Invalid Combinations (Use-case Mismatches)
    # Case A: ECDH (key agreement) used for Digital signatures
    res_ecdh_sig = assess_algorithm("ECDH", "Digital signatures")
    check(res_ecdh_sig["risk_level"] == RISK_INVALID, "ECDH for Digital signatures returns Invalid use case")
    check(not res_ecdh_sig["is_valid_use_case"], "ECDH for Digital signatures marked is_valid_use_case = False")
    check("ML-DSA" in res_ecdh_sig["recommendation"], "Invalid signature use case recommends signature scheme (ML-DSA), not a KEM")

    # Case B: ML-KEM (KEM) used for Code signing
    res_mlkem_sig = assess_algorithm("ML-KEM", "Code signing")
    check(res_mlkem_sig["risk_level"] == RISK_INVALID, "ML-KEM for Code signing returns Invalid use case")
    check("ML-DSA" in res_mlkem_sig["recommendation"], "Invalid signature use case recommends signature scheme (ML-DSA)")

    # Case C: ML-DSA (signatures) used for TLS key exchange
    res_mldsa_ke = assess_algorithm("ML-DSA", "TLS key exchange")
    check(res_mldsa_ke["risk_level"] == RISK_INVALID, "ML-DSA for TLS key exchange returns Invalid use case")
    check("ML-KEM" in res_mldsa_ke["recommendation"], "Invalid key exchange use case recommends KEM (ML-KEM)")

    # Case D: AES (symmetric) used for Certificate authentication
    res_aes_auth = assess_algorithm("AES", "Certificate authentication")
    check(res_aes_auth["risk_level"] == RISK_INVALID, "AES for Certificate authentication returns Invalid use case")

    # 11. Test Unknown Algorithm
    res_unknown = assess_algorithm("SuperQuantumCipher9000", "Data at rest")
    check(res_unknown["risk_level"] == RISK_UNKNOWN, "Unknown algorithm handled gracefully")
    check(not res_unknown["is_valid_use_case"], "Unknown algorithm marked invalid")

    # 12. Test Missing / Empty Inputs
    res_missing_algo = assess_algorithm("", "Code signing")
    check(res_missing_algo["risk_level"] == RISK_UNKNOWN, "Empty algorithm string returns Unknown/Missing")
    check("Missing" in res_missing_algo["reason"], "Missing algorithm returns informative error message")

    res_none_algo = assess_algorithm(None, None)
    check(res_none_algo["risk_level"] == RISK_UNKNOWN, "None input handled safely without exception")

    print("\n----------------------------------------------------------------------")
    print(f"TEST RESULTS: {passed}/{total} tests passed ({int(passed/total*100)}%)")
    print("----------------------------------------------------------------------")

    if passed == total:
        print("\nAll tests passed successfully!")
        return 0
    else:
        print(f"\n{total - passed} tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
