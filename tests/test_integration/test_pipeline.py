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


def test_extraction_error_block_cannot_be_marked_safe():
    result = process_extracted_blocks(
        [{
            "id": "page1-error",
            "page_slide": 1,
            "block_type": "OCR_UNAVAILABLE",
            "text": "",
            "extraction_error": "OCR produced no text",
        }],
        document_id="synthetic-extraction-failure",
        source_file="scanned.pdf",
        file_type="pdf",
    )

    assert result["status"] == "failed"
    assert result["safe_to_process"] is False
    assert result["validation"]["passed"] is False
    assert any(
        issue["code"] == "UPSTREAM_FAILURE"
        for issue in result["validation"]["issues"]
    )
    assert "OCR produced no text" not in str(result)


def test_explicit_extraction_errors_cannot_be_marked_safe():
    result = process_extracted_blocks(
        [{
            "id": "page1",
            "page_slide": 1,
            "block_type": "paragraph",
            "text": "Some extracted text without known PII.",
        }],
        document_id="synthetic-extraction-summary-error",
        source_file="sample.pdf",
        file_type="pdf",
        extraction_errors=[{
            "block_id": "page2-error",
            "error": "Sensitive source-specific detail",
        }],
    )

    assert result["status"] == "failed"
    assert result["safe_to_process"] is False
    assert result["validation"]["passed"] is False
    assert "Sensitive source-specific detail" not in str(result)


def test_extraction_result_handoff_preserves_errors():
    from src.integration.pipeline import process_extraction_result

    result = process_extraction_result(
        {
            "blocks": [{
                "id": "page1",
                "page_slide": 1,
                "block_type": "paragraph",
                "text": "Contact alex.smith@example.com",
            }],
            "errors": [{
                "block_id": "page2-error",
                "error": "OCR failed",
            }],
            "complete": False,
        },
        document_id="handoff-test",
        source_file="sample.pdf",
        file_type="pdf",
    )

    assert result["safe_to_process"] is False
    assert result["status"] == "failed"
    assert any(
        issue["code"] == "UPSTREAM_FAILURE"
        for issue in result["validation"]["issues"]
    )
    assert "alex.smith@example.com" not in str(result)


def test_incomplete_extraction_without_error_details_fails_closed():
    from src.integration.pipeline import process_extraction_result

    result = process_extraction_result(
        {"blocks": [], "errors": [], "complete": False},
        document_id="incomplete-test",
        source_file="sample.pdf",
        file_type="pdf",
    )

    assert result["safe_to_process"] is False
    assert result["status"] == "failed"


def test_malformed_extraction_result_fails_closed():
    from src.integration.pipeline import process_extraction_result

    result = process_extraction_result(
        {"blocks": "not-a-list", "errors": [], "complete": True},
        document_id="malformed-test",
        source_file="sample.pdf",
        file_type="pdf",
    )

    assert result["safe_to_process"] is False
    assert result["status"] == "failed"


def test_empty_extraction_result_fails_closed():
    from src.integration.pipeline import process_extraction_result

    result = process_extraction_result(
        {"blocks": [], "errors": [], "complete": True},
        document_id="empty-test",
        source_file="empty.pdf",
        file_type="pdf",
    )

    assert result["safe_to_process"] is False
    assert result["status"] == "failed"
    assert result["validation"]["passed"] is False


def test_non_dictionary_extraction_block_fails_closed():
    from src.integration.pipeline import process_extraction_result

    result = process_extraction_result(
        {"blocks": ["invalid block"], "errors": [], "complete": True},
        document_id="bad-block-test",
        source_file="bad.pdf",
        file_type="pdf",
    )

    assert result["safe_to_process"] is False
    assert result["status"] == "failed"
