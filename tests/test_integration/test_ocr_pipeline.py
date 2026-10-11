import pymupdf
from PIL import Image, ImageDraw, ImageFont

from src.extraction.extraction_engine import extract_pdf_mixed
from src.integration.pipeline import process_extracted_blocks


def test_scanned_pdf_ocr_to_redaction_and_validation(tmp_path):
    image_path = tmp_path / "synthetic_scan.png"
    pdf_path = tmp_path / "synthetic_scan.pdf"

    # Create an image containing synthetic text, not a real document.
    image = Image.new("RGB", (1600, 350), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 48
    )
    draw.text(
        (40, 100),
        "Contact alex.smith@example.com for assistance.",
        fill="black",
        font=font,
    )
    image.save(image_path)

    # Embed the image in a PDF; the PDF has no selectable native text.
    pdf = pymupdf.open()
    page = pdf.new_page(width=800, height=175)
    page.insert_image(page.rect, filename=str(image_path))
    pdf.save(pdf_path)
    pdf.close()

    extracted = extract_pdf_mixed(str(pdf_path), pdf_path.name)
    extracted_text = "\n".join(block["text"] for block in extracted)

    assert "alex.smith@example.com" in extracted_text

    result = process_extracted_blocks(
        extracted,
        document_id="synthetic-ocr-001",
        source_file=pdf_path.name,
        file_type="pdf",
    )

    sanitized_text = "\n".join(
        block["text"]
        for unit in result["units"]
        for block in unit["blocks"]
    )

    assert "alex.smith@example.com" not in sanitized_text
    assert "[REDACTED:EMAIL]" in sanitized_text
    assert result["validation"]["passed"] is True
    assert result["safe_to_process"] is True
    assert "alex.smith@example.com" not in str(result["audit_events"])


def test_ocr_text_is_split_into_separate_paragraphs(monkeypatch, tmp_path):
    from src.extraction import extraction_engine

    pdf_path = tmp_path / "two_paragraph_scan.pdf"
    pdf = pymupdf.open()
    page = pdf.new_page()
    page.insert_image(page.rect, filename=str(
        tmp_path / "synthetic_scan.png"
    )) if (tmp_path / "synthetic_scan.png").exists() else None
    pdf.save(pdf_path)
    pdf.close()

    # Force the OCR result to contain two paragraphs, independently
    # of the OCR engine's recognition accuracy.
    class FakePage:
        def get_text(self, _kind):
            return ""

        def get_pixmap(self, **_kwargs):
            class Pixmap:
                width = 1
                height = 1
                samples = b"\xff\xff\xff"
            return Pixmap()

    class FakeDocument:
        def __iter__(self):
            return iter([FakePage()])

        def close(self):
            pass

    monkeypatch.setattr(extraction_engine.fitz, "open", lambda _path: FakeDocument())
    monkeypatch.setattr(
        extraction_engine.pytesseract,
        "image_to_string",
        lambda _image: "First paragraph with enough text.\n\nSecond paragraph with enough text.",
    )

    blocks = extraction_engine.extract_pdf_mixed(str(pdf_path), pdf_path.name)

    assert [block["text"] for block in blocks] == [
        "First paragraph with enough text.",
        "Second paragraph with enough text.",
    ]


def test_extract_all_documents_discovers_supported_extensions(monkeypatch, tmp_path):
    from src.extraction import extraction_engine as engine

    (tmp_path / "notes.docx").touch()
    (tmp_path / "slides.PPTX").touch()
    (tmp_path / "policy.pdf").touch()
    (tmp_path / "ignore.txt").touch()
    (tmp_path / "~$temporary.docx").touch()
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "other.pdf").touch()

    calls = []

    def fake_extractor(file_path, file_name):
        calls.append(file_name)
        return [{
            "id": f"{file_name}_0",
            "file": file_name,
            "text": "example extracted text",
            "page_slide": 1,
        }]

    monkeypatch.setattr(engine, "extract_docx_native", fake_extractor)
    monkeypatch.setattr(engine, "extract_pptx_directory", fake_extractor)
    monkeypatch.setattr(engine, "extract_pdf_mixed", fake_extractor)

    result = engine.extract_all_documents(str(tmp_path))

    assert calls == ["other.pdf", "notes.docx", "policy.pdf", "slides.PPTX"]
    assert result["total_blocks"] == 4
    assert len(result["reports"]) == 4
    assert result["complete"] is True
    assert result["retention"] is None


def test_extract_all_documents_missing_directory_fails_closed(tmp_path):
    from src.extraction.extraction_engine import extract_all_documents

    result = extract_all_documents(str(tmp_path / "does-not-exist"))

    assert result["total_blocks"] == 0
    assert result["blocks"] == []
    assert result["reports"] == []
    assert result["complete"] is False


def test_empty_directory_has_no_successful_extraction(tmp_path):
    from src.extraction.extraction_engine import extract_all_documents

    result = extract_all_documents(str(tmp_path))

    assert result["complete"] is False
    assert result["blocks"] == []
    assert result["errors"]


def test_corrupt_document_is_reported_without_crashing(tmp_path):
    from src.extraction.extraction_engine import extract_all_documents

    (tmp_path / "broken.docx").write_bytes(b"not a real DOCX file")
    result = extract_all_documents(str(tmp_path))

    assert result["complete"] is False
    assert result["errors"]
    assert result["reports"][0]["status"] == "failed"
