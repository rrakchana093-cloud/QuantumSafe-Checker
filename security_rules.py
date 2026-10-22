"""QuantumSafe Cryptographic Security Rules Engine.

This module provides rule-based evaluation of cryptographic algorithms against
quantum computing threats (Shor's and Grover's algorithms) and evaluates alignment
with current NIST Post-Quantum Cryptography (PQC) standards (FIPS 203, 204, 205).

Owned by Member 2 (Security Rules & Algorithm Standards).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Path to the authoritative algorithms database
ALGORITHMS_JSON_PATH = Path(__file__).parent / "algorithms.json"

# Standard risk categories
RISK_HIGH = "High risk"
RISK_LOWER = "Lower quantum risk"
RISK_SAFE = "Quantum-safe"
RISK_INVALID = "Invalid use case"
RISK_UNKNOWN = "Unknown algorithm"

# Cryptographic role taxonomy
ROLE_KEY_ESTABLISHMENT = "key_establishment"
ROLE_DIGITAL_SIGNATURE = "digital_signature"
ROLE_SYMMETRIC_ENCRYPTION = "symmetric_encryption"

# Canonical use-case to role mapping
USE_CASE_ROLE_MAP: Dict[str, str] = {
    # Key establishment / transport / encryption
    "tls key exchange": ROLE_KEY_ESTABLISHMENT,
    "tls key establishment": ROLE_KEY_ESTABLISHMENT,
    "hybrid key exchange": ROLE_KEY_ESTABLISHMENT,
    "secure messaging": ROLE_KEY_ESTABLISHMENT,
    "vpn key exchange": ROLE_KEY_ESTABLISHMENT,
    "key transport": ROLE_KEY_ESTABLISHMENT,
    "data encryption": ROLE_KEY_ESTABLISHMENT,  # In asymmetric contexts like RSA
    # Digital signatures / authentication
    "digital signatures": ROLE_DIGITAL_SIGNATURE,
    "certificate authentication": ROLE_DIGITAL_SIGNATURE,
    "code signing": ROLE_DIGITAL_SIGNATURE,
    "document signing": ROLE_DIGITAL_SIGNATURE,
    "transaction signing": ROLE_DIGITAL_SIGNATURE,
    "firmware signing": ROLE_DIGITAL_SIGNATURE,
    "long-lived signatures": ROLE_DIGITAL_SIGNATURE,
    "root-of-trust signing": ROLE_DIGITAL_SIGNATURE,
    # Symmetric data protection
    "data at rest": ROLE_SYMMETRIC_ENCRYPTION,
    "application encryption": ROLE_SYMMETRIC_ENCRYPTION,
    "backup encryption": ROLE_SYMMETRIC_ENCRYPTION,
    "secure transport": ROLE_SYMMETRIC_ENCRYPTION,
}

# Cache for algorithm lookup
_DB_CACHE: Optional[Dict[str, Any]] = None
_ALIAS_MAP: Optional[Dict[str, Dict[str, Any]]] = None


def load_algorithms_database() -> Dict[str, Any]:
    """Load the algorithms database from algorithms.json, caching in memory."""
    global _DB_CACHE, _ALIAS_MAP
    if _DB_CACHE is not None and _ALIAS_MAP is not None:
        return _DB_CACHE

    if not ALGORITHMS_JSON_PATH.exists():
        raise FileNotFoundError(f"Algorithms database not found at {ALGORITHMS_JSON_PATH}")

    with open(ALGORITHMS_JSON_PATH, "r", encoding="utf-8") as file:
        data = json.load(file)

    _DB_CACHE = data
    _ALIAS_MAP = {}

    for algo in data.get("algorithms", []):
        algo_id = algo["id"].upper()
        _ALIAS_MAP[algo_id] = algo
        _ALIAS_MAP[algo["name"].upper()] = algo
        for alias in algo.get("aliases", []):
            _ALIAS_MAP[alias.upper()] = algo

    return _DB_CACHE


def get_supported_algorithms() -> List[Dict[str, Any]]:
    """Return list of all supported algorithm definitions."""
    db = load_algorithms_database()
    return db.get("algorithms", [])


def find_algorithm(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Look up an algorithm by name, identifier, or recognized alias."""
    if not name_or_alias:
        return None
    load_algorithms_database()
    assert _ALIAS_MAP is not None
    normalized = name_or_alias.strip().upper()
    return _ALIAS_MAP.get(normalized)


def normalize_use_case(use_case: str) -> str:
    """Normalize use-case string for matching."""
    return use_case.strip().lower()


def get_use_case_role(use_case: str) -> Optional[str]:
    """Determine the intended cryptographic role of a use case."""
    normalized = normalize_use_case(use_case)
    return USE_CASE_ROLE_MAP.get(normalized)


def validate_use_case(
    algo_def: Dict[str, Any], use_case: str
) -> Tuple[bool, str]:
    """Check if the provided algorithm can be legitimately applied to the use case.
    
    Returns:
        (is_valid, explanation_message)
    """
    normalized_use_case = normalize_use_case(use_case)
    intended_role = get_use_case_role(use_case)
    supported_roles = algo_def.get("supported_roles", [])
    valid_use_cases = [u.lower() for u in algo_def.get("valid_use_cases", [])]

    # Exact match in listed valid use cases
    if normalized_use_case in valid_use_cases:
        return True, "Valid use case for this algorithm."

    # Role-based evaluation
    if intended_role and intended_role in supported_roles:
        return True, f"Valid use case aligned with cryptographic role: {intended_role}."

    # Handle mismatched roles
    algo_name = algo_def.get("name", "Algorithm")
    algo_role_desc = ", ".join(supported_roles) if supported_roles else "unspecified"
    
    if intended_role == ROLE_DIGITAL_SIGNATURE and ROLE_DIGITAL_SIGNATURE not in supported_roles:
        return False, (
            f"Use-case mismatch: '{algo_name}' is designed for {algo_role_desc} "
            f"and cannot produce digital signatures or authenticate certificates."
        )

    if intended_role == ROLE_KEY_ESTABLISHMENT and ROLE_KEY_ESTABLISHMENT not in supported_roles:
        return False, (
            f"Use-case mismatch: '{algo_name}' is designed for {algo_role_desc} "
            f"and cannot perform key exchange or key encapsulation."
        )

    if intended_role == ROLE_SYMMETRIC_ENCRYPTION and ROLE_SYMMETRIC_ENCRYPTION not in supported_roles:
        return False, (
            f"Use-case mismatch: '{algo_name}' is an asymmetric algorithm and is not suitable "
            f"for bulk symmetric encryption."
        )

    return False, (
        f"'{use_case}' is not a recognized or supported use case for {algo_name}. "
        f"Valid use cases include: {', '.join(algo_def.get('valid_use_cases', []))}."
    )


def assess_algorithm(
    algorithm: Optional[str],
    use_case: Optional[str],
    key_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Assess a cryptographic algorithm against quantum threats for an intended use case.

    Args:
        algorithm: Name, acronym, or alias of the cryptographic algorithm (e.g. 'RSA', 'ML-KEM').
        use_case: Operational application (e.g. 'TLS key exchange', 'Code signing').
        key_size: Optional key size in bits (e.g. 2048, 256).

    Returns:
        Structured assessment dictionary with risk level, technical rationale,
        quantum threat profile, contextual recommendation, and authoritative NIST references.
    """
    # 1. Validate missing inputs
    if not algorithm or not str(algorithm).strip():
        return {
            "algorithm": "",
            "use_case": use_case or "",
            "is_valid_use_case": False,
            "risk_level": RISK_UNKNOWN,
            "reason": "Missing algorithm name. An algorithm must be specified for security assessment.",
            "quantum_threat": "Assessment cannot proceed without an algorithm identifier.",
            "recommendation": "Provide a supported classical or post-quantum algorithm name.",
            "prioritization_score": 0,
            "score_rationale": "N/A - Missing input",
            "references": [],
            "standardization_status": "unspecified",
            "caveats": "Assessment incomplete due to missing parameters.",
        }

    cleaned_algo = str(algorithm).strip()
    cleaned_use_case = str(use_case).strip() if use_case else "General use"

    # 2. Look up algorithm definition
    algo_def = find_algorithm(cleaned_algo)
    if not algo_def:
        return {
            "algorithm": cleaned_algo,
            "use_case": cleaned_use_case,
            "is_valid_use_case": False,
            "risk_level": RISK_UNKNOWN,
            "reason": (
                f"Unknown algorithm '{cleaned_algo}'. The algorithm is not currently recognized "
                f"in the QuantumSafe standards catalog. Supported algorithms include: "
                f"RSA, ECDH, ECDSA, AES, ML-KEM, ML-DSA, SLH-DSA, and predecessor candidate names."
            ),
            "quantum_threat": "Quantum exposure cannot be evaluated for unrecognized algorithms.",
            "recommendation": (
                "Verify the algorithm name or check the QuantumSafe catalog for supported standards "
                "(RSA, ECDH, ECDSA, AES, ML-KEM, ML-DSA, SLH-DSA)."
            ),
            "prioritization_score": 50,
            "score_rationale": "Default prioritization score (50/100) assigned to uncataloged algorithms requiring manual review.",
            "references": [
                {
                    "standard_id": "NIST IR 8547",
                    "title": "Transition to Post-Quantum Cryptography Standards",
                    "published": "2024",
                    "url": "https://csrc.nist.gov/pubs/ir/8547/ipd",
                }
            ],
            "standardization_status": "unrecognized",
            "caveats": "Manual cryptographic review required for non-cataloged algorithms.",
        }

    # 3. Validate use-case compatibility
    is_valid_use, use_case_message = validate_use_case(algo_def, cleaned_use_case)
    intended_role = get_use_case_role(cleaned_use_case)

    if not is_valid_use:
        # Determine appropriate replacement based strictly on the INTENDED role of the use case
        if intended_role == ROLE_DIGITAL_SIGNATURE:
            replacement_advice = (
                "For digital signature use cases, select a standardized signature scheme "
                "such as ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)."
            )
        elif intended_role == ROLE_KEY_ESTABLISHMENT:
            replacement_advice = (
                "For key establishment use cases, select a standardized key encapsulation mechanism "
                "such as ML-KEM (NIST FIPS 203)."
            )
        elif intended_role == ROLE_SYMMETRIC_ENCRYPTION:
            replacement_advice = (
                "For bulk data encryption, use an authenticated symmetric cipher such as AES-256 (NIST FIPS 197)."
            )
        else:
            replacement_advice = algo_def.get("alternative", "Consult NIST SP 800-57 for appropriate algorithms.")

        return {
            "algorithm": algo_def["name"],
            "family": algo_def.get("family", ""),
            "use_case": cleaned_use_case,
            "is_valid_use_case": False,
            "risk_level": RISK_INVALID,
            "reason": use_case_message,
            "quantum_threat": (
                "Using an algorithm outside its mathematically intended domain compromises security "
                "even on classical computers before quantum attacks are considered."
            ),
            "recommendation": replacement_advice,
            "prioritization_score": 100,
            "score_rationale": (
                "Application-defined prioritization score (100/100): Mismatched cryptographic roles "
                "represent an immediate architecture defect."
            ),
            "references": [algo_def.get("reference", {})],
            "standardization_status": algo_def.get("standardization_status", "unknown"),
            "caveats": "Cryptographic algorithms must never be repurposed across distinct security roles.",
        }

    # 4. Valid assessment: determine role-contextual recommendation and risk adjustments
    risk_level = algo_def.get("base_risk", RISK_HIGH)
    recommendation = algo_def.get("alternative", "")
    explanation = algo_def.get("explanation", "")
    quantum_threat = algo_def.get("quantum_threat", "")
    prioritization_score = algo_def.get("prioritization_score", 50)
    score_rationale = algo_def.get("score_rationale", "")

    # Role-specific recommendation refinement for dual-role algorithms like RSA
    if algo_def["id"] == "RSA":
        if intended_role == ROLE_DIGITAL_SIGNATURE:
            recommendation = (
                "Migrate digital signatures to ML-DSA (NIST FIPS 204) for general application signing "
                "or SLH-DSA (NIST FIPS 205) for high-assurance firmware and PKI root authorities."
            )
        elif intended_role == ROLE_KEY_ESTABLISHMENT:
            recommendation = (
                "Migrate key transport/exchange to ML-KEM (NIST FIPS 203). During transition, "
                "deploy hybrid key exchange combining classical ECDH with ML-KEM-768."
            )

    # Key size adjustments for AES
    if algo_def["id"] == "AES" and key_size is not None:
        if key_size < 192:
            risk_level = RISK_HIGH
            prioritization_score = 75
            explanation += (
                f" Note: The specified key size ({key_size}-bit) is weakened to only {key_size // 2} bits "
                f"of quantum security by Grover's algorithm, which falls below the NIST minimum security threshold."
            )
            recommendation = "Upgrade immediately from AES-128 to AES-256 to guarantee at least 128 bits of quantum security margin."
        else:
            risk_level = RISK_LOWER
            prioritization_score = 25
            recommendation = f"Maintain AES-{key_size} with authenticated encryption (e.g. GCM mode) and quantum-safe key exchange."

    # Legacy / predecessor note enrichment
    status = algo_def.get("standardization_status")
    if status == "legacy_predecessor":
        successor = algo_def.get("successor_standard", "the standardized NIST standard")
        recommendation = f"Upgrade legacy implementation to {successor}. Do not deploy pre-standard versions in production."
    elif status == "candidate_in_progress":
        recommendation = (
            "Deploy finalized standards (ML-DSA / FIPS 204 or SLH-DSA / FIPS 205) for immediate production; "
            "track NIST draft standard FN-DSA for future compact signature requirements."
        )

    ref = algo_def.get("reference", {})
    references_list = [ref] if ref else []

    return {
        "algorithm": algo_def["name"],
        "algorithm_id": algo_def["id"],
        "family": algo_def.get("family", ""),
        "use_case": cleaned_use_case,
        "cryptographic_role": algo_def.get("cryptographic_role", ""),
        "is_valid_use_case": True,
        "risk_level": risk_level,
        "reason": explanation,
        "quantum_threat": quantum_threat,
        "recommendation": recommendation,
        "prioritization_score": prioritization_score,
        "score_rationale": score_rationale,
        "standardization_status": status,
        "status_label": algo_def.get("status_label", ""),
        "references": references_list,
        "reference_citation": f"{ref.get('standard_id', '')} · {ref.get('title', '')} ({ref.get('published', '')})",
        "caveats": (
            "Prioritization scores are application-defined planning metrics, not certified mathematical measurements. "
            "No algorithm is immune to all attacks; secure implementations require side-channel defenses, authenticated modes, "
            "and sound cryptographic agility."
        ),
    }
