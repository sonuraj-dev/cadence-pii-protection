from src.detection.detector import detect_pii_entities


def _matches(text, entity_type):
    return [
        text[item["start"]:item["end"]]
        for item in detect_pii_entities(text)
        if item["type"] == entity_type
    ]


def test_email_detected_with_exact_span():
    text = "Contact alex.smith@example.com"
    assert "alex.smith@example.com" in _matches(text, "EMAIL_ADDRESS")


def test_employee_id_detected():
    text = "Employee ID EMP-41077"
    assert "EMP-41077" in _matches(text, "EMP_ID")


def test_phone_detected():
    text = "Call +1 (646) 555-0188"
    assert "+1 (646) 555-0188" in _matches(text, "PHONE_NUMBER")


def test_date_of_birth_detected():
    text = "DOB 12 March 1995"
    assert "DOB 12 March 1995" in _matches(text, "DATE_OF_BIRTH")


def test_person_detected_in_sentence():
    text = "Naomi K. Osadebe is an employee."
    assert "Naomi K. Osadebe" in _matches(text, "PERSON")


def test_contact_prefix_is_not_misclassified_as_person():
    text = "Contact Naomi K. Osadebe"
    matches = _matches(text, "PERSON")
    assert "Contact Naomi" not in matches


def test_long_account_number_is_not_classified_as_phone():
    text = "Account number 123456789012"
    assert _matches(text, "PHONE_NUMBER") == []


def test_all_detected_spans_are_valid():
    samples = [
        "Contact alex.smith@example.com",
        "Employee ID EMP-41077",
        "Call +1 (646) 555-0188",
        "DOB 12 March 1995",
        "Naomi K. Osadebe is an employee.",
        "Account number 123456789012",
    ]
    for text in samples:
        for item in detect_pii_entities(text):
            assert 0 <= item["start"] < item["end"] <= len(text)
            assert text[item["start"]:item["end"]].strip()
