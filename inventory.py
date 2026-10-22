
import csv


REQUIRED_COLUMNS = ["asset_name", "algorithm", "use_case"]


def load_inventory(file_path):
    """Load and validate a cryptographic inventory CSV file."""

    try:
        with open(file_path, "r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                return [], ["CSV file is empty or has no header."]

            # Remove surrounding whitespace from column names.
            reader.fieldnames = [
                name.strip() if name else ""
                for name in reader.fieldnames
            ]

            if not any(reader.fieldnames):
                return [], ["CSV file has no valid column names."]

            if len(reader.fieldnames) != len(set(reader.fieldnames)):
                return [], ["CSV contains duplicate column names."]

            missing_columns = [
                column for column in REQUIRED_COLUMNS
                if column not in reader.fieldnames
            ]

            if missing_columns:
                return [], [
                    "Missing required columns: "
                    + ", ".join(missing_columns)
                ]

            valid_records = []
            errors = []

            for row_number, row in enumerate(reader, start=2):
                # Detect malformed rows with extra values.
                if None in row:
                    errors.append(
                        f"Row {row_number}: too many values in the row."
                    )
                    continue

                # Normalize whitespace in field values.
                record = {
                    key: value.strip() if value is not None else ""
                    for key, value in row.items()
                    if key is not None
                }

                # Notes is optional.
                record.setdefault("notes", "")

                empty_fields = [
                    column for column in REQUIRED_COLUMNS
                    if not record.get(column, "")
                ]

                if empty_fields:
                    errors.append(
                        f"Row {row_number}: empty required fields: "
                        + ", ".join(empty_fields)
                    )
                    continue

                valid_records.append(record)

            return valid_records, errors

    except (OSError, UnicodeError, csv.Error) as error:
        return [], [f"Unable to read CSV file: {error}"]
