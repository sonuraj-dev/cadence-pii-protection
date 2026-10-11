"""
Cadence PII Protection - Extraction Engine
Extracts DOCX, PPTX, and PDF documents while preserving available structure.
Handles: DOCX (native), PPTX (directory), PDF (scanned/mixed with OCR)
"""

import os
import re

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None
    Image = None
from pathlib import Path
from typing import List, Dict

try:
    import fitz # PyMuPDF
except:
    fitz = None

try:
    from docx import Document
except:
    Document = None

try:
    from pptx import Presentation
except:
    Presentation = None

def extract_docx_native(file_path: str, file_name: str) -> List[Dict]:
    """Extract DOCX paragraphs and table cells while preserving their text."""
    blocks = []
    if Document is None:
        return blocks
    doc = Document(file_path)
    block_id = 0
    for para in doc.paragraphs:
        text = para.text.strip()
        if not text:
            continue
        blocks.append({
            "id": f"{file_name}_{block_id}",
            "file": file_name,
            "type": "PROCESS_DOCUMENT_NATIVE",
            "text": text,
            "page_slide": 1,
            "block_type": para.style.name if para.style else "Normal",
            "char_count": len(text)
        })
        block_id += 1
    # Tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                text = cell.text.strip()
                if text:
                    blocks.append({
                        "id": f"{file_name}_{block_id}",
                        "file": file_name,
                        "type": "PROCESS_DOCUMENT_NATIVE",
                        "text": text,
                        "page_slide": 1,
                        "block_type": "Table",
                        "char_count": len(text)
                    })
                    block_id += 1
    return blocks

def extract_pptx_directory(file_path: str, file_name: str) -> List[Dict]:
    """Extract text-bearing PowerPoint shapes by slide."""
    blocks = []
    if Presentation is None:
        return blocks
    prs = Presentation(file_path)
    block_id = 0
    for slide_idx, slide in enumerate(prs.slides, 1):
        for shape in slide.shapes:
            if hasattr(shape, "text") and shape.text.strip():
                text = shape.text.strip()
                blocks.append({
                    "id": f"{file_name}_slide{slide_idx}_{block_id}",
                    "file": file_name,
                    "type": "PRESENTATION_DIRECTORY",
                    "text": text,
                    "page_slide": slide_idx,
                    "block_type": f"Slide_{slide_idx}",
                    "char_count": len(text)
                })
                block_id += 1
    return blocks

def extract_pdf_mixed(file_path: str, file_name: str) -> List[Dict]:
    """Extract native PDF text; report unreadable scanned pages as errors."""
    blocks = []
    if fitz is None:
        raise RuntimeError("PyMuPDF is required for PDF extraction")
    doc = fitz.open(file_path)
    block_id = 0
    for page_idx, page in enumerate(doc, 1):
        text = page.get_text("text").strip()
        if text:
            # Split into paragraphs to preserve structure
            for para in re.split(r'\n\s*\n', text):
                para = para.strip()
                if len(para) > 10:
                    blocks.append({
                        "id": f"{file_name}_page{page_idx}_{block_id}",
                        "file": file_name,
                        "type": "POLICY_DOCUMENT_SCANNED_MIXED",
                        "text": para,
                        "page_slide": page_idx,
                        "block_type": "PDF_Text",
                        "char_count": len(para)
                    })
                    block_id += 1
        else:
            # OCR fallback for scanned pages. Never invent extracted text.
            ocr_text = ""
            ocr_error = None

            if pytesseract is None or Image is None:
                ocr_error = "OCR dependencies unavailable"
            else:
                try:
                    pix = page.get_pixmap(dpi=200, alpha=False)
                    image = Image.frombytes(
                        "RGB", (pix.width, pix.height), pix.samples
                    )
                    ocr_text = pytesseract.image_to_string(image).strip()
                except Exception as exc:
                    ocr_error = f"OCR failed: {type(exc).__name__}"

            if ocr_text:
                for para in re.split(r"\n\s*\n", ocr_text):
                    para = para.strip()
                    if not para:
                        continue
                    blocks.append({
                        "id": f"{file_name}_page{page_idx}_{block_id}",
                        "file": file_name,
                        "type": "POLICY_DOCUMENT_SCANNED_MIXED",
                        "text": para,
                        "page_slide": page_idx,
                        "block_type": "PDF_OCR",
                        "char_count": len(para),
                    })
                    block_id += 1
            else:
                blocks.append({
                    "id": f"{file_name}_page{page_idx}_{block_id}",
                    "file": file_name,
                    "type": "POLICY_DOCUMENT_SCANNED_MIXED",
                    "text": "",
                    "page_slide": page_idx,
                    "block_type": "OCR_UNAVAILABLE",
                    "char_count": 0,
                    "extraction_error": ocr_error or
                        "OCR produced no text; page requires review",
                })
                block_id += 1
    return blocks

def extract_all_documents(docs_path: str = "/content/docs") -> Dict:
    """Extract supported files and report incomplete extraction without hiding errors."""
    all_blocks = []
    reports = []
    errors = []
    docs_path = Path(docs_path)

    if not docs_path.is_dir():
        return {
            "total_blocks": 0,
            "blocks": [],
            "reports": [],
            "retention": None,
            "retention_status": "not_measured_no_reference_text",
            "errors": [{
                "block_id": "input",
                "error": "Input directory is missing or invalid",
            }],
            "complete": False,
        }

    extractors = {
        ".docx": (extract_docx_native, "PROCESS_DOCUMENT_NATIVE"),
        ".pptx": (extract_pptx_directory, "PRESENTATION_DIRECTORY"),
        ".pdf": (extract_pdf_mixed, "POLICY_DOCUMENT_SCANNED_MIXED"),
    }

    for file_path in sorted(docs_path.rglob("*")):
        if not file_path.is_file() or file_path.name.startswith("~$"):
            continue

        extractor_info = extractors.get(file_path.suffix.lower())
        if extractor_info is None:
            continue

        extractor, document_type = extractor_info
        relative_name = str(file_path.relative_to(docs_path))

        try:
            blocks = extractor(str(file_path), file_path.name)
        except Exception as exc:
            errors.append({
                "block_id": relative_name,
                "error": f"Document extraction failed: {type(exc).__name__}",
            })
            reports.append({
                "file": relative_name,
                "blocks": 0,
                "type": document_type,
                "status": "failed",
            })
            continue

        all_blocks.extend(blocks)
        reports.append({
            "file": relative_name,
            "blocks": len(blocks),
            "type": document_type,
            "status": "extracted",
        })

    errors.extend(
        {
            "block_id": block["id"],
            "page_slide": block.get("page_slide"),
            "error": block["extraction_error"],
        }
        for block in all_blocks
        if block.get("extraction_error")
    )

    if not reports:
        errors.append({
            "block_id": "input",
            "error": "No supported PDF, DOCX, or PPTX documents were found",
        })

    return {
        "total_blocks": len(all_blocks),
        "blocks": all_blocks,
        "reports": reports,
        "retention": None,
        "retention_status": "not_measured_no_reference_text",
        "errors": errors,
        "complete": bool(reports) and not errors,
    }


# For backward compatibility
def extract_documents(*args, **kwargs):
    return extract_all_documents(*args, **kwargs)

if __name__ == "__main__":
    result = extract_all_documents()
    print(f"Total blocks: {result['total_blocks']}")
    for r in result['reports']:
        print(f"{r['file']} | {r['type']} | {r['blocks']} blocks")
