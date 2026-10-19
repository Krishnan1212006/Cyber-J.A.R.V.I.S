"""Create simple PowerPoint presentations or PDF reports."""

from pathlib import Path

PLUGIN = {
    "name": "document_creator",
    "description": (
        "Create a PowerPoint presentation or PDF report from supplied text. "
        "Use this for requests to make, export, or generate a PPT, PPTX, or PDF."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "format": {"type": "STRING", "description": "pptx or pdf"},
            "title": {"type": "STRING", "description": "Document title"},
            "content": {"type": "STRING", "description": "Text; separate PPTX slides with blank lines"},
            "output_path": {"type": "STRING", "description": "Destination file path"},
        },
        "required": ["format", "title", "content", "output_path"],
    },
}


def _safe_path(value: str, extension: str) -> Path:
    if not value.strip():
        raise ValueError("an output path is required")
    path = Path(value).expanduser()
    if path.suffix.lower() != extension:
        path = path.with_suffix(extension)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _create_pptx(title: str, content: str, path: Path) -> None:
    from pptx import Presentation

    presentation = Presentation()
    for index, block in enumerate(content.split("\n\n")):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        slide = presentation.slides.add_slide(presentation.slide_layouts[1])
        slide.shapes.title.text = lines[0] if lines else title
        body = slide.placeholders[1].text_frame
        body.clear()
        for line in (lines[1:] or ([title] if index == 0 else [])):
            paragraph = body.paragraphs[0] if not body.text else body.add_paragraph()
            paragraph.text = line.lstrip("- *")
    presentation.save(path)


def _create_pdf(title: str, content: str, path: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Title"]), Spacer(1, 0.2 * inch)]
    for line in content.splitlines():
        text = line.strip()
        if text:
            story.extend([Paragraph(text.replace("&", "&amp;"), styles["BodyText"]), Spacer(1, 0.08 * inch)])
    SimpleDocTemplate(str(path), pagesize=letter).build(story)


def run(parameters: dict, player=None, session_memory=None) -> str:
    try:
        document_format = str(parameters.get("format", "")).lower().lstrip(".")
        title = str(parameters.get("title", "JARVIS Report")).strip()
        content = str(parameters.get("content", "")).strip()
        if document_format not in {"ppt", "pptx", "pdf"}:
            return "Choose either pptx or pdf as the document format."
        if not content:
            return "I need content before creating the document."
        extension = ".pdf" if document_format == "pdf" else ".pptx"
        path = _safe_path(str(parameters.get("output_path", "")), extension)
        if extension == ".pdf":
            _create_pdf(title, content, path)
        else:
            _create_pptx(title, content, path)
        return f"Created the {document_format.upper()} document at {path}."
    except ImportError as exc:
        return f"The document library is missing: {exc}. Run pip install -r requirements.txt."
    except Exception as exc:
        return f"Document creation failed: {exc}"