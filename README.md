# Cadence PII Protection

A Python backend prototype for extracting document content, detecting selected
personally identifiable information (PII), redacting detected spans, and
blocking documents when validation fails.

## Pipeline

1. Extract text from PDF, DOCX, and PPTX documents.
2. Detect supported PII patterns and record their text spans.
3. Build the normalized document structure.
4. Redact detected spans.
5. Validate the result and allow downstream processing only when safety checks pass.

## Requirements

- Python 3.12 recommended
- Tesseract OCR installed on the operating system for scanned PDF fallback
- Python dependencies from `requirements.txt`

On Ubuntu:

    sudo apt update
    sudo apt install tesseract-ocr

Set up the project:

    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -r requirements.txt

## Tests and diagnostic evaluation

Run the test suite:

    .venv/bin/python -m pytest -q

Run the detector's small synthetic diagnostic set:

    PYTHONPATH=. .venv/bin/python scripts/evaluate_detector.py

The synthetic evaluation is a development diagnostic, not evidence of
production-level PII detection accuracy.

## Integration interfaces

- `src/extraction/extraction_engine.py` provides document extraction functions,
  including `extract_all_documents(docs_path=...)`.
- `src/integration/pipeline.py` provides `process_extraction_result(...)` to
  pass the complete extraction result, including completion status and errors,
  into the integration pipeline.
- `src/redaction/` contains redaction and document safety-validation logic.

Inspect function signatures in the source files for required arguments and
the exact output schema before integrating this prototype into another service.

## Safety and limitations

- If extraction is incomplete or malformed, downstream processing must fail
  closed. Do not treat a failed result as safe.
- The detector currently uses rule-based patterns and has limited person-name
  recognition. It will not identify every possible PII value or format.
- Residual validation checks a limited set of patterns; passing validation is
  not a guarantee that all PII has been removed.
- OCR quality depends on document quality and installed OCR support.
- Retention is not considered measured unless a reference-text comparison is
  performed. Do not claim 100% retention without measured evidence.
- Test results establish behavior only for the covered test cases.
- Use synthetic or appropriately authorized data for development. Do not send
  confidential documents to external services without explicit authorization
  and an approved data-handling process.

This repository is a prototype and should not be treated as a certified
production security control.
