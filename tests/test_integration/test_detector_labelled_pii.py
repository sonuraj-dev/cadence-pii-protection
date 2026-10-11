from src.detection.detector import detect_pii_entities
from src.integration.pipeline import process_extracted_blocks


def matches(text, entity_type):
    return [
        text[item["start"]:item["end"]]
        for item in detect_pii_entities(text)
        if item["type"] == entity_type
    ]


def test_labelled_account_number_detected():
    text = "Account number: 123456789012"
    assert matches(text, "ACCOUNT_NUMBER") == [text]


def test_labelled_date_of_birth_detected():
    text = "Date of birth: 14 March 1998"
    assert matches(text, "DATE_OF_BIRTH") == [text]


def test_numeric_dob_detected():
    text = "DOB: 14/03/1998"
    assert matches(text, "DATE_OF_BIRTH") == [text]


def test_generic_address_and_heading_words_are_not_person_names():
    text = (
        "Synthetic Customer Record\n"
        "Mailing address: 123 Demo Street, Example City, ZZ 00000"
    )
    assert matches(text, "PERSON") == []


def test_labelled_account_number_is_redacted_and_export_safe():
    text = "Account number: 123456789012"
    result = process_extracted_blocks(
        [{"id": "b1", "page_slide": 1, "text": text}],
        document_id="synthetic-account-test",
        source_file="test.txt",
        file_type="txt",
    )
    assert result["safe_to_process"] is True
    sanitized = result["units"][0]["blocks"][0]["text"]
    assert "123456789012" not in sanitized
    assert "[REDACTED:ACCOUNT_NUMBER]" in sanitized


def test_labelled_dob_is_redacted_and_export_safe():
    text = "Date of birth: 14 March 1998"
    result = process_extracted_blocks(
        [{"id": "b1", "page_slide": 1, "text": text}],
        document_id="synthetic-dob-test",
        source_file="test.txt",
        file_type="txt",
    )
    assert result["safe_to_process"] is True
    sanitized = result["units"][0]["blocks"][0]["text"]
    assert "14 March 1998" not in sanitized
    assert "[REDACTED:DATE_OF_BIRTH]" in sanitized


def test_account_number_left_in_sanitized_text_fails_validation():
    from src.integration.pipeline import residual_validator

    document = {
        "units": [{
            "blocks": [{
                "block_id": "b1",
                "text": "Account number: 123456789012",
            }]
        }]
    }
    findings = residual_validator(document)
    assert any(item["type"] == "ACCOUNT_NUMBER" for item in findings)
    assert all("123456789012" not in str(item) for item in findings)


def test_residual_validator_flags_labelled_address():
    from src.integration.pipeline import residual_validator

    document = {"units": [{"blocks": [{
        "block_id": "1",
        "text": "Mailing address: 123 Demo Street, Example City, ZZ 00000",
    }]}]}
    findings = residual_validator(document)
    assert any(item["type"] == "ADDRESS" for item in findings)


def test_residual_validator_flags_person_in_internal_note():
    from src.integration.pipeline import residual_validator

    document = {"units": [{"blocks": [{
        "block_id": "1",
        "text": "Internal note: Alex Example requested a statement copy.",
    }]}]}
    findings = residual_validator(document)
    assert any(item["type"] == "PERSON" for item in findings)


def test_residual_validator_does_not_flag_ordinary_heading():
    from src.integration.pipeline import residual_validator

    document = {"units": [{"blocks": [{
        "block_id": "1",
        "text": "Ordinary heading: Example Customer Record",
    }]}]}
    assert residual_validator(document) == []
