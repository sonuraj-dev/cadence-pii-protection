from src.detection.detector import detect_pii_entities
from src.integration.pipeline import process_extracted_blocks, residual_validator


def spans(text, kind):
    return [
        text[item["start"]:item["end"]]
        for item in detect_pii_entities(text)
        if item["type"] == kind
    ]


def test_existing_core_types_and_exact_person_span():
    text = "Contact Naomi K. Osadebe at naomi@example.com; EMP-41077; +1 (646) 555-0188."
    assert "Naomi K. Osadebe" in spans(text, "PERSON")
    assert "naomi@example.com" in spans(text, "EMAIL_ADDRESS")
    assert "EMP-41077" in spans(text, "EMP_ID")
    assert "+1 (646) 555-0188" in spans(text, "PHONE_NUMBER")


def test_labelled_account_and_dob_keep_labels_for_compatibility():
    account = "Account number: 123456789012"
    dob = "Date of birth: 14 March 1998"
    assert spans(account, "ACCOUNT_NUMBER") == [account]
    assert spans(dob, "DATE_OF_BIRTH") == [dob]


def test_address_is_detected_as_one_span():
    text = "Mailing address: 123 Main Street, Sampletown, ZZ 00000"
    assert spans(text, "ADDRESS") == [text]


def test_labelled_ssn_is_detected():
    text = "SSN: 123-45-6789"
    assert spans(text, "SSN") == [text]


def test_luhn_valid_payment_card_is_detected():
    text = "Card number: 4111 1111 1111 1111"
    assert spans(text, "PAYMENT_CARD") == ["4111 1111 1111 1111"]


def test_invalid_luhn_card_candidate_is_not_flagged():
    assert spans("Card number: 4111 1111 1111 1112", "PAYMENT_CARD") == []


def test_iban_and_labelled_ip_are_detected():
    assert spans("IBAN GB82 WEST 1234 5698 7654 32", "IBAN")
    assert spans("Client IP: 192.168.1.10", "IP_ADDRESS") == ["Client IP: 192.168.1.10"]


def test_generic_heading_is_not_person():
    assert spans("Synthetic Customer Record", "PERSON") == []


def test_contact_label_is_not_included_in_person_span():
    text = "Contact Naomi K. Osadebe"
    assert spans(text, "PERSON") == ["Naomi K. Osadebe"]


def test_detector_returns_valid_non_overlapping_spans():
    text = (
        "Contact Alex Smith at alex@example.com; "
        "Account number 123456789012; DOB 12/12/1990; "
        "Call +1 (646) 555-0188."
    )
    findings = detect_pii_entities(text)
    for finding in findings:
        assert 0 <= finding["start"] < finding["end"] <= len(text)
    ordered = sorted(findings, key=lambda item: item["start"])
    for left, right in zip(ordered, ordered[1:]):
        assert right["start"] >= left["end"]


def test_new_types_are_redacted_and_residual_scan_is_clear():
    text = "SSN: 123-45-6789; Card: 4111 1111 1111 1111; IP: 192.168.1.10"
    result = process_extracted_blocks(
        [{"id": "synthetic-1", "page_slide": 1, "text": text}],
        document_id="synthetic-test",
        source_file="synthetic.txt",
        file_type="txt",
    )
    sanitized = result["units"][0]["blocks"][0]["text"]
    assert "123-45-6789" not in sanitized
    assert "4111 1111 1111 1111" not in sanitized
    assert "192.168.1.10" not in sanitized


def test_residual_validator_does_not_echo_sensitive_values():
    document = {"units": [{"blocks": [{"block_id": "b1", "text": "SSN: 123-45-6789"}]}]}
    findings = residual_validator(document)
    assert all("123-45-6789" not in str(item) for item in findings)


def test_employee_label_does_not_get_redacted_instead_of_identifier():
    text = "Employee ID EMP-41077"
    found = [text[item["start"]:item["end"]] for item in detect_pii_entities(text) if item["type"] == "EMP_ID"]
    assert found == ["EMP-41077"]


def test_ocr_spaced_email_and_period_employee_id():
    text = "n.osadebe @cadencefg.com; Tobias Lindgvist (EMP.40522)"
    findings = detect_pii_entities(text)
    values = [(item["type"], text[item["start"]:item["end"]]) for item in findings]
    assert ("EMAIL_ADDRESS", "n.osadebe @cadencefg.com") in values
    assert ("EMP_ID", "EMP.40522") in values


def test_contextual_names_in_narrative_and_labelled_rows():
    narrative = "Naomi K. Osadebe is an employee."
    row = "Contact: Mireille Dubois-Kane | Escalation"
    assert "Naomi K. Osadebe" in spans(narrative, "PERSON")
    assert "Mireille Dubois-Kane" in spans(row, "PERSON")
    assert spans("Synthetic Customer Record", "PERSON") == []


def test_country_specific_ids_require_labels_and_format():
    pan_text = "PAN: ABCDE1234F"
    pesel_text = "PESEL: 44051401458"
    tin_text = "TIN: TX-123456"
    assert any(x["type"] == "PAN" for x in detect_pii_entities(pan_text))
    assert any(x["type"] == "PESEL" for x in detect_pii_entities(pesel_text))
    assert any(x["type"] == "TIN" for x in detect_pii_entities(tin_text))
    assert not any(x["type"] == "PAN" for x in detect_pii_entities("Reference ABCDE1234F"))


def test_residual_validator_catches_ocr_email_employee_id_and_labelled_ids():
    document = {"units": [{"blocks": [{"block_id": "b1", "text":
        "n.osadebe @cadencefg.com EMP.40522 PAN: ABCDE1234F"}]}]}
    kinds = {item["type"] for item in residual_validator(document)}
    assert {"EMAIL", "EMPLOYEE_ID", "PAN"} <= kinds
