
import csv

from inventory import load_inventory


def create_csv(tmp_path, content):
    """Create a temporary CSV file for testing."""
    file_path = tmp_path / "test_inventory.csv"
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_valid_inventory(tmp_path):
    content = (
        "asset_name,algorithm,use_case,notes\n"
        "Website,RSA,digital_signature,Public website\n"
        "Storage,AES-256,symmetric_encryption,Stored data\n"
    )

    file_path = create_csv(tmp_path, content)
    records, errors = load_inventory(file_path)

    assert len(records) == 2
    assert errors == []
    assert records[0]["asset_name"] == "Website"


def test_missing_required_column(tmp_path):
    content = (
        "asset_name,algorithm,notes\n"
        "Website,RSA,Public website\n"
    )

    file_path = create_csv(tmp_path, content)
    records, errors = load_inventory(file_path)

    assert records == []
    assert any("use_case" in error for error in errors)


def test_empty_required_value(tmp_path):
    content = (
        "asset_name,algorithm,use_case,notes\n"
        "Website,RSA,,Public website\n"
    )

    file_path = create_csv(tmp_path, content)
    records, errors = load_inventory(file_path)

    assert records == []
    assert any("use_case" in error for error in errors)


def test_empty_csv(tmp_path):
    file_path = create_csv(tmp_path, "")

    records, errors = load_inventory(file_path)

    assert records == []
    assert errors


def test_whitespace_normalization(tmp_path):
    content = (
        " asset_name , algorithm , use_case , notes \n"
        " Website , RSA , digital_signature , Public website \n"
    )

    file_path = create_csv(tmp_path, content)
    records, errors = load_inventory(file_path)

    assert errors == []
    assert records[0]["asset_name"] == "Website"
    assert records[0]["algorithm"] == "RSA"


def test_missing_file():
    records, errors = load_inventory("file_that_does_not_exist.csv")

    assert records == []
    assert errors


def test_optional_notes_column(tmp_path):
    content = (
        "asset_name,algorithm,use_case\n"
        "Website,RSA,digital_signature\n"
    )

    file_path = create_csv(tmp_path, content)
    records, errors = load_inventory(file_path)

    assert errors == []
    assert records[0]["notes"] == ""


def test_duplicate_headers(tmp_path):
    content = (
        "asset_name,algorithm,use_case,algorithm\n"
        "Website,RSA,digital_signature,ECDH\n"
    )

    file_path = create_csv(tmp_path, content)
    records, errors = load_inventory(file_path)

    assert records == []
    assert any("duplicate" in error.lower() for error in errors)
