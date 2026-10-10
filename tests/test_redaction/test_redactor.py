import pytest

from src.redaction.redactor import redact_text


def test_redacts_email():
    text = "Contact john@example.com for help."
    entities = [{
        "type": "EMAIL",
        "start": 8,
        "end": 24,
        "confidence": 0.99,
        "method": "email_pattern",
    }]

    sanitized, audit = redact_text(text, entities)

    assert sanitized == "Contact [REDACTED:EMAIL] for help."
    assert "john@example.com" not in sanitized
    assert len(audit) == 1
    assert audit[0]["type"] == "EMAIL"
    assert audit[0]["redacted"] is True
    assert "john@example.com" not in str(audit)


def test_redacts_multiple_entities():
    text = "Email a@example.com or call 9876543210."
    entities = [
        {
            "type": "EMAIL",
            "start": 6,
            "end": 19,
            "confidence": 0.99,
            "method": "email_pattern",
        },
        {
            "type": "PHONE",
            "start": 28,
            "end": 38,
            "confidence": 0.95,
            "method": "phone_pattern",
        },
    ]

    sanitized, audit = redact_text(text, entities)

    assert "a@example.com" not in sanitized
    assert "9876543210" not in sanitized
    assert len(audit) == 2


def test_empty_entity_list_preserves_text():
    text = "This document contains no detected PII."

    sanitized, audit = redact_text(text, [])

    assert sanitized == text
    assert audit == []


def test_invalid_offsets_are_rejected():
    text = "Contact john@example.com"

    with pytest.raises(ValueError):
        redact_text(
            text,
            [{"type": "EMAIL", "start": 8, "end": 200}],
        )


def test_overlapping_spans_are_rejected():
    text = "abcdefghij"
    entities = [
        {"type": "PERSON", "start": 0, "end": 6},
        {"type": "ID", "start": 4, "end": 9},
    ]

    with pytest.raises(ValueError, match="overlapping"):
        redact_text(text, entities)


def test_original_pii_is_not_in_audit():
    text = "Contact john@example.com"
    entities = [{
        "type": "EMAIL",
        "start": 8,
        "end": 24,
        "confidence": 0.99,
    }]

    _, audit = redact_text(text, entities)

    assert "john@example.com" not in str(audit)