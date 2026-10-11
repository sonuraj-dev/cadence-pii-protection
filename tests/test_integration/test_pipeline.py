import pytest

from src.integration.pipeline import (
    build_document,
    process_extracted_blocks,
    residual_validator,
)


def test_build_document_uses_nested_contract_and_canonical_labels():
    text = "Contact alex.smith@example.com for help."
    document = build_document(
        [{
            "id": "p1-b1",
            "page_slide": 1,
            "block_type": "paragraph",
            "text": text,
        }],
        document_id="synthetic-001",
        source_file="sample.pdf",
        file_type="pdf",
    )

    block = document["units"][0]["blocks"][0]
    assert document["schema_version"] == "1.0"
    assert block["text"] == text
    assert block["entities"][0]["type"] == "EMAIL"
    assert text[
        block["entities"][0]["start"]:block["entities"][0]["end"]
    ] == "alex.smith@example.com"


def test_invalid_detector_span_is_rejected(monkeypatch):
    from src.integration import pipeline

    monkeypatch.setattr(
        pipeline,
        "detect_pii_entities",
        lambda text, meta=None: [{
            "type": "EMAIL_ADDRESS",
            "start": 0,
            "end": len(text) + 1,
            "confidence": 1.0,
            "method": "test",
        }],
    )

    with pytest.raises(ValueError, match="Invalid detector span"):
        pipeline.build_document(
            [{"text": "hello", "page_slide": 1}],
            document_id="test",
            source_file="test.pdf",
            file_type="pdf",
        )


def test_residual_validator_reports_no_raw_value():
    document = {
        "units": [{
            "blocks": [{
                "block_id": "b1",
                "text": "Email alex.smith@example.com",
            }]
        }]
    }
    findings = residual_validator(document)

    assert findings
    assert all("alex.smith@example.com" not in str(f) for f in findings)


def test_synthetic_email_is_redacted_and_marked_safe():
    result = process_extracted_blocks(
        [{
            "id": "p1-b1",
            "page_slide": 1,
            "block_type": "paragraph",
            "text": "Contact alex.smith@example.com for help.",
        }],
        document_id="synthetic-002",
        source_file="synthetic.pdf",
        file_type="pdf",
    )

    assert result["safe_to_process"] is True
    block = result["units"][0]["blocks"][0]
    assert "alex.smith@example.com" not in block["text"]
    assert residual_validator(result) == []
    assert "alex.smith@example.com" not in str(result.get("audit_events", []))
