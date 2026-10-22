import csv
import io

from inventory import load_inventory
from report import generate_report


def test_inventory_to_report_pipeline():
    records, errors = load_inventory("data/sample_inventory.csv")

    assert errors == []
    assert len(records) == 8

    assessments = [
        {
            "risk_level": "Example",
            "explanation": "Mock assessment for testing",
            "recommendation": "Replace with actual assessment",
        }
        for record in records
    ]

    report_csv = generate_report(records, assessments)

    report_rows = list(csv.DictReader(io.StringIO(report_csv)))

    assert len(report_rows) == 8
    assert report_rows[0]["asset_name"] == "Website Certificate"
    assert report_rows[0]["risk_level"] == "Example"