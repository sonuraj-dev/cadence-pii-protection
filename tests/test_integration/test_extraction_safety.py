import pymupdf

from src.extraction.extraction_engine import extract_pdf_mixed


def test_scanned_page_is_not_fabricated_as_extracted_text(tmp_path):
    pdf_path = tmp_path / "scanned.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    # Leave the page blank to simulate a page with no extractable text.
    doc.save(pdf_path)
    doc.close()

    blocks = extract_pdf_mixed(str(pdf_path), "scanned.pdf")

    assert len(blocks) == 1
    assert blocks[0]["text"] == ""
    assert blocks[0]["block_type"] == "OCR_UNAVAILABLE"
    assert blocks[0]["extraction_error"]


def test_native_pdf_text_is_extracted(tmp_path):
    pdf_path = tmp_path / "native.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Synthetic policy text with enough characters.")
    doc.save(pdf_path)
    doc.close()

    blocks = extract_pdf_mixed(str(pdf_path), "native.pdf")

    assert blocks
    assert any("Synthetic policy text" in block["text"] for block in blocks)
    assert not any(block.get("extraction_error") for block in blocks)
