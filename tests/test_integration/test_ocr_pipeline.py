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
