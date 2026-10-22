
import csv
import io

import pytest

from report import generate_report


def test_generate_report():
    inventory = [
        {
            "asset_name": "Website Certificate",
            "algorithm": "RSA",
            "use_case": "digital_signature",
            "notes": "Public website",
        }
    ]

    assessments = [
        {
            "risk_level": "Example",
            "explanation": "Mock assessment",
            "recommendation": "Example recommendation",
        }
    ]

    report = generate_report(inventory, assessments)
    rows = list(csv.DictReader(io.StringIO(report)))

    assert len(rows) == 1
    assert rows[0]["asset_name"] == "Website Certificate"
    assert rows[0]["algorithm"] == "RSA"
    assert rows[0]["risk_level"] == "Example"
    assert rows[0]["explanation"] == "Mock assessment"


def test_report_headers():
    report = generate_report([], [])
    reader = csv.reader(io.StringIO(report))

    headers = next(reader)

    assert headers == [
        "asset_name",
        "algorithm",
        "use_case",
        "risk_level",
        "explanation",
        "recommendation",
        "notes",
    ]


def test_empty_results():
    report = generate_report([], [])

    assert len(list(csv.reader(io.StringIO(report)))) == 1


def test_missing_optional_values():
    inventory = [
        {
            "asset_name": "Test Asset",
            "algorithm": "AES-256",
            "use_case": "symmetric_encryption",
        }
    ]

    assessments = [{}]

    report = generate_report(inventory, assessments)
    rows = list(csv.DictReader(io.StringIO(report)))

    assert rows[0]["notes"] == ""
    assert rows[0]["risk_level"] == ""
    assert rows[0]["recommendation"] == ""


def test_special_characters_and_commas():
    inventory = [
        {
            "asset_name": "Website, Primary",
            "algorithm": "RSA",
            "use_case": "digital_signature",
            "notes": 'Contains "important" data, for testing',
        }
    ]

    assessments = [
        {
            "risk_level": "Example",
            "explanation": "Test, with commas",
            "recommendation": 'Check "configuration"',
        }
    ]

    report = generate_report(inventory, assessments)
    rows = list(csv.DictReader(io.StringIO(report)))

    assert rows[0]["asset_name"] == "Website, Primary"
    assert rows[0]["notes"] == 'Contains "important" data, for testing'
    assert rows[0]["explanation"] == "Test, with commas"
    assert rows[0]["recommendation"] == 'Check "configuration"'


def test_mismatched_record_counts():
    inventory = [
        {
            "asset_name": "Website",
            "algorithm": "RSA",
            "use_case": "digital_signature",
        }
    ]

    with pytest.raises(ValueError):
        generate_report(inventory, [])
