
import csv
import io


REPORT_COLUMNS = [
    "asset_name",
    "algorithm",
    "use_case",
    "risk_level",
    "explanation",
    "recommendation",
    "notes",
]


def generate_report(inventory_records, assessment_results):
    """Generate a CSV report from inventory and assessment results.

    Returns:
        str: CSV content that can be saved or downloaded.
    """

    if len(inventory_records) != len(assessment_results):
        raise ValueError(
            "Inventory records and assessment results "
            "must have the same number of entries."
        )

    output = io.StringIO(newline="")

    writer = csv.DictWriter(
        output,
        fieldnames=REPORT_COLUMNS,
        extrasaction="ignore",
    )

    writer.writeheader()

    for asset, assessment in zip(inventory_records, assessment_results):
        row = {
            "asset_name": asset.get("asset_name", ""),
            "algorithm": asset.get("algorithm", ""),
            "use_case": asset.get("use_case", ""),
            "risk_level": assessment.get("risk_level", ""),
            "explanation": assessment.get("explanation", ""),
            "recommendation": assessment.get("recommendation", ""),
            "notes": asset.get("notes", ""),
        }

        writer.writerow(row)

    return output.getvalue()
