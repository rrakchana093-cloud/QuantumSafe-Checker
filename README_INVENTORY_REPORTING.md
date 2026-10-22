# QuantumSafe — Quantum-Safe Security Checker

## 1. Project Overview

QuantumSafe is an educational prototype developed for the Quantum Cryptography & Security hackathon track.

It accepts a CSV inventory of cryptographic assets, supports algorithm risk assessment through a separate security rules module, and generates an assessment report with recommendations.

**Disclaimer:** This is an educational prototype. It is not a production security scanner, formal security assessment, or security certification system.

## 2. Features

- Load cryptographic asset inventories from CSV files.
- Validate required columns and required field values.
- Normalize whitespace in column names and field values.
- Report missing columns, duplicate headers, and malformed rows.
- Generate CSV assessment reports from supplied assessment results.
- Handle missing optional values and special characters in CSV fields.
- Run automated tests using pytest.

## 3. Technology Stack

- Python
- Python CSV module
- pytest
- Streamlit (for the planned dashboard, maintained by the UI and integration member)

## 4. Project Structure

```text
Quantumsafe_checker/
├── app.py
├── inventory.py
├── report.py
├── security_rules.py
├── algorithms.json
├── data/
│   └── sample_inventory.csv
├── tests/
│   ├── test_inventory.py
│   ├── test_report.py
│   └── test_security_rules.py
└── README.md
```

Some files may be added or completed by other team members during integration.

## 5. CSV Input Format

The inventory CSV uses these columns:

| Column | Required | Description |
|---|---|---|
| asset_name | Yes | Name of the cryptographic asset |
| algorithm | Yes | Algorithm used by the asset |
| use_case | Yes | Purpose of the algorithm |
| notes | No | Additional asset information |

Example:

```csv
asset_name,algorithm,use_case,notes
Website Certificate,RSA,digital_signature,Public website
Internal Key Exchange,ECDH,key_establishment,Internal service
Data Encryption,AES-256,symmetric_encryption,Stored data
```

Use fictional demonstration data. Never include private keys, passwords, credentials, or confidential company information.

## 6. Setup

Create and activate a Python virtual environment.

On Windows Command Prompt:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install pytest
```

## 7. Running the Inventory Module

The inventory loader can be called from Python:

```python
from inventory import load_inventory

records, errors = load_inventory("data/sample_inventory.csv")

print("Valid records:", len(records))
print("Validation errors:", errors)
```

The loader returns valid records and a list of validation errors.

## 8. Generating a Report

The report module accepts inventory records and corresponding assessment results:

```python
from inventory import load_inventory
from report import generate_report

records, errors = load_inventory("data/sample_inventory.csv")

if errors:
    print(errors)
else:
    # Replace these illustrative results with actual
    # results from the security assessment module.
    assessments = [
        {
            "risk_level": "Example",
            "explanation": "Illustrative mock result",
            "recommendation": "Replace with actual assessment"
        }
        for record in records
    ]

    report_csv = generate_report(records, assessments)

    with open("assessment_report.csv", "w", newline="", encoding="utf-8") as file:
        file.write(report_csv)
```

The example assessment values are mock data, not real security findings.

## 9. Running Tests

Run the inventory and reporting tests separately:

```cmd
python -m pytest tests/test_inventory.py -v
python -m pytest tests/test_report.py -v
```

Run all available tests:

```cmd
python -m pytest -v
```

## 10. Team Responsibilities

- Member 1: Streamlit user interface and integration.
- Member 2: Cryptographic security research, assessment rules, and algorithm metadata.
- Member 3: Inventory validation, CSV reporting, automated tests, quality assurance, and documentation.

## 11. Limitations

- Security assessment results depend on the separately implemented assessment rules.
- Mock results are only for development and testing.
- Successful CSV validation does not establish that an algorithm or deployment is secure.
- The prototype does not provide formal security certification.

## 12. Security References

The cryptographic claims and algorithm recommendations should be supported by authoritative references, such as relevant NIST post-quantum cryptography standards. Add the exact references used by the security research member before the final submission.
