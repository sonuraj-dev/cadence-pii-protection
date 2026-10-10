from copy import deepcopy

import pytest

from src.redaction.document_pipeline import redact_document


def sample_document():
    return {
        "schema_version": "1.0",
        "document_id": "synthetic-001",
        "source_file": "synthetic_sample.pdf",
        "file_type": "pdf",
        "status": "detected",
        "units": [{
            "unit_type": "page",
            "unit_number": 1,
            "blocks": [{
                "block_id": "p1-b1",
                "type": "paragraph",
                "order": 0,
                "text": "Contact john@example.com for help.",
                "entities": [{
                    "type": "EMAIL", "start": 8, "end": 24,
                    "confidence": 0.99, "method": "email_pattern"
                }]
            }]
        }],
        "errors": [],
    }


def no_residuals(_sanitized_document):
    return []


def test_document_redaction_preserves_structure_and_removes_entities():
    result = redact_document(sample_document(), residual_validator=no_residuals)
    block = result["units"][0]["blocks"][0]
    assert block["text"] == "Contact [REDACTED:EMAIL] for help."
    assert "entities" not in block
    assert result["units"][0]["unit_type"] == "page"
    assert result["safe_to_process"] is True
    assert result["validation"]["passed"] is True


def test_audit_has_traceability_but_not_original_pii():
    result = redact_document(sample_document(), residual_validator=no_residuals)
    event = result["audit_events"][0]
    assert event["document_id"] == "synthetic-001"
    assert event["unit_number"] == 1
    assert event["block_id"] == "p1-b1"
    assert event["entity_type"] == "EMAIL"
    assert event["action"] == "redacted"
    assert "john@example.com" not in repr(event)


def test_missing_validator_fails_closed():
    result = redact_document(sample_document())
    assert result["safe_to_process"] is False
    assert result["validation"]["passed"] is False
    assert any(i["code"] == "VALIDATOR_REQUIRED" for i in result["validation"]["issues"])


def test_residual_findings_fail_closed():
    result = redact_document(
        sample_document(),
        residual_validator=lambda _: [{"code": "RESIDUAL_PII", "message": "A configured recognizer found a residual."}],
    )
    assert result["safe_to_process"] is False
    assert result["status"] == "failed"


def test_invalid_span_fails_closed():
    doc = sample_document()
    doc["units"][0]["blocks"][0]["entities"][0]["end"] = 999
    result = redact_document(doc, residual_validator=no_residuals)
    assert result["safe_to_process"] is False
    assert result["status"] == "failed"


def test_overlapping_spans_fail_closed():
    doc = sample_document()
    doc["units"][0]["blocks"][0]["entities"].append({
        "type": "PERSON", "start": 8, "end": 15, "confidence": 0.7, "method": "test"
    })
    result = redact_document(doc, residual_validator=no_residuals)
    assert result["safe_to_process"] is False


def test_empty_entities_preserve_text():
    doc = sample_document()
    doc["units"][0]["blocks"][0]["entities"] = []
    result = redact_document(
        doc,
        residual_validator=lambda _: [{"code": "RESIDUAL_EMAIL", "message": "Configured validator found a residual email."}],
    )
    assert result["units"][0]["blocks"][0]["text"] == "Contact john@example.com for help."
    # Empty detector output is not proof of safety; the residual validator blocks the document.
    assert result["safe_to_process"] is False


def test_input_is_not_mutated():
    doc = sample_document()
    before = deepcopy(doc)
    redact_document(doc, residual_validator=no_residuals)
    assert doc == before
