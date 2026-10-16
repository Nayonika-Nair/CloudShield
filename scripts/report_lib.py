"""Shared ReportLab helpers for the two submission PDFs."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, KeepTogether, PageBreak, PageTemplate, Paragraph, Preformatted, Spacer, Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".tmp" / "img"
REPO = "https://github.com/Nayonika-Nair/CloudShield"
NAVY = colors.HexColor("#1f3a5f")
LIGHT = colors.HexColor("#e8edf4")
GRID = colors.HexColor("#c0cad8")

_ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontName="Helvetica", fontSize=9.6, leading=13.2, spaceAfter=5)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10.2, spaceAfter=0)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=8.2, leading=10.4, spaceAfter=0)
CELLB = ParagraphStyle("cellb", parent=CELL, fontName="Helvetica-Bold")
CAP = ParagraphStyle("cap", parent=BODY, fontSize=8.6, leading=11, textColor=colors.HexColor("#33475f"), alignment=TA_CENTER, spaceBefore=3, spaceAfter=10)
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=NAVY, spaceBefore=6, spaceAfter=10)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontName="Helvetica-Bold", fontSize=12.6, leading=16, textColor=NAVY, spaceBefore=11, spaceAfter=5)
H3 = ParagraphStyle("h3", parent=_ss["Heading3"], fontName="Helvetica-Bold", fontSize=10.4, leading=13, textColor=colors.HexColor("#2d4a73"), spaceBefore=8, spaceAfter=3)
TITLE = ParagraphStyle("title", parent=H1, fontSize=26, leading=31, spaceBefore=40, spaceAfter=10)
SUB = ParagraphStyle("sub", parent=BODY, fontSize=12, leading=16, textColor=colors.HexColor("#33475f"))
CODE = ParagraphStyle("code", fontName="Courier", fontSize=7, leading=8.4, textColor=colors.HexColor("#111b2a"), backColor=colors.HexColor("#f3f6fa"),
                      borderColor=GRID, borderWidth=0.4, borderPadding=4, spaceBefore=3, spaceAfter=8)


def esc(t) -> str:
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Report(BaseDocTemplate):
    def __init__(self, path: Path, title: str, footer_title: str):
        super().__init__(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=18 * mm,
                         title=title, author="CloudShield project team", subject=footer_title)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.footer_title = footer_title
        self.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=self._decorate)])
        self.fig_no = 0
        self.tab_no = 0
        self._key = 0

    def _decorate(self, canv, doc):
        if doc.page == 1:
            return
        canv.saveState()
        canv.setFont("Helvetica", 7.8)
        canv.setFillColor(colors.HexColor("#5a6b7e"))
        canv.drawString(doc.leftMargin, A4[1] - 12 * mm, self.footer_title)
        canv.drawRightString(A4[0] - doc.rightMargin, A4[1] - 12 * mm, "CloudShield")
        canv.setStrokeColor(GRID)
        canv.line(doc.leftMargin, A4[1] - 14 * mm, A4[0] - doc.rightMargin, A4[1] - 14 * mm)
        canv.drawCentredString(A4[0] / 2, 10 * mm, f"Page {doc.page}")
        canv.restoreState()

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in ("h1", "h2"):
            level = 0 if flowable.style.name == "h1" else 1
            key = "sec-" + re.sub(r"[^a-z0-9]+", "-", flowable.getPlainText().lower()).strip("-")[:60]   # stable across passes
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(flowable.getPlainText(), key, level=level, closed=level > 0)
            self.notify("TOCEntry", (level, flowable.getPlainText(), self.page, key))


def toc() -> TableOfContents:
    t = TableOfContents()
    t.levelStyles = [
        ParagraphStyle("t0", fontName="Helvetica-Bold", fontSize=9.6, leading=13, leftIndent=0, spaceBefore=3),
        ParagraphStyle("t1", fontName="Helvetica", fontSize=8.8, leading=11.5, leftIndent=12),
    ]
    return t


def h1(text: str, key=None) -> Paragraph:
    return Paragraph(esc(text), H1)


def h2(text: str) -> Paragraph:
    return Paragraph(esc(text), H2)


def h3(text: str) -> Paragraph:
    return Paragraph(esc(text), H3)


def p(text: str, style=BODY) -> Paragraph:
    return Paragraph(text, style)  # callers may include <b>, <i>, <font> markup; use esc() for raw data


def bullets(items: list[str], style=BODY) -> list:
    return [Paragraph("&bull;&nbsp;&nbsp;" + t, ParagraphStyle("b", parent=style, leftIndent=12, firstLineIndent=-9, spaceAfter=2)) for t in items]


def _resized(path: Path, max_px: int) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    out = CACHE / (re.sub(r"[^A-Za-z0-9]+", "_", str(path.relative_to(ROOT))) + f"_{max_px}.png")
    if not out.exists() or out.stat().st_mtime < path.stat().st_mtime:
        im = PILImage.open(path).convert("RGB")
        if im.width > max_px:
            im = im.resize((max_px, round(im.height * max_px / im.width)), PILImage.LANCZOS)
        im.save(out, optimize=True)
    return out


def fig(doc: Report, path: str | Path, caption: str, *, width_mm: float = 170, max_h_mm: float = 215, px: int = 1700):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        raise FileNotFoundError(path)
    img_path = _resized(path, px)
    with PILImage.open(img_path) as im:
        w, h = im.size
    wd = width_mm * mm
    ht = wd * h / w
    if ht > max_h_mm * mm:
        ht = max_h_mm * mm
        wd = ht * w / h
    doc.fig_no += 1
    img = Image(str(img_path), width=wd, height=ht)
    img.hAlign = "CENTER"
    box = Table([[img]], colWidths=[min(doc.width, wd + 4)], style=[("BOX", (0, 0), (-1, -1), 0.4, GRID), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                                                       ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)])
    box.hAlign = "CENTER"
    return KeepTogether([box, Paragraph(f"<b>Figure {doc.fig_no}.</b> {caption}", CAP)])


def table(doc: Report, header: list[str], rows: list[list], widths_mm: list[float], *, caption: str | None = None, zebra: bool = True,
          bold_first: bool = False, font: ParagraphStyle = CELL):
    data = [[Paragraph(f"<b>{esc(h)}</b>", font) for h in header]]
    for r in rows:
        data.append([c if not isinstance(c, (str, int, float)) else
                     Paragraph(c if isinstance(c, str) and c.startswith("<b>") and c.endswith("</b>") else
                               (("<b>%s</b>" if bold_first and i == 0 else "%s") % esc(c)), font)
                     for i, c in enumerate(r)])
    t = Table(data, colWidths=[w * mm for w in widths_mm], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.3, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")])]
    t.setStyle(TableStyle(style))
    out = [t]
    if caption:
        doc.tab_no += 1
        out = [t, Paragraph(f"<b>Table {doc.tab_no}.</b> {caption}", CAP)]
    return out


def code(text: str, max_cols: int = 118) -> Preformatted:
    lines = []
    for line in text.rstrip("\n").splitlines():
        while len(line) > max_cols:
            lines.append(line[:max_cols])
            line = "    " + line[max_cols:]
        lines.append(line)
    return Preformatted("\n".join(lines), CODE)


def excerpt(path: str, start: int, end: int) -> str:
    src = (ROOT / path).read_text(encoding="utf-8").splitlines()
    return "\n".join(f"{i + 1:>4}  {src[i]}" for i in range(start - 1, min(end, len(src))))


# --------------------------------------------------------------------- evidence data
def load_register() -> list[dict]:
    items: list[dict] = []
    for f in sorted((ROOT / "docs" / "screenshots" / ".register").glob("*.json")):
        items += json.loads(f.read_text(encoding="utf-8"))
    return items


def junit_cases(path: Path) -> list[dict]:
    root = ET.parse(path).getroot()
    out = []
    for tc in root.iter("testcase"):
        status = "passed"
        if tc.find("failure") is not None or tc.find("error") is not None:
            status = "failed"
        elif tc.find("skipped") is not None:
            status = "skipped"
        out.append({"module": tc.get("classname", "").split(".")[1] if "." in tc.get("classname", "") else tc.get("classname", ""),
                    "name": tc.get("name"), "time": float(tc.get("time", 0)), "status": status})
    return out


def coverage_total(result_txt: Path) -> tuple[str, dict[str, str]]:
    txt = result_txt.read_text(encoding="utf-8", errors="replace")
    per = {}
    for m in re.finditer(r"^(app\\[\w\\]+\.py)\s+(\d+)\s+(\d+)\s+(\d+)%", txt, re.M):
        per[m.group(1)] = m.group(4) + "%"
    tot = re.search(r"^TOTAL\s+(\d+)\s+(\d+)\s+(\d+)%", txt, re.M)
    return (tot.group(3) + "%" if tot else "n/a"), per


def mutation_rows() -> list[dict]:
    d = ROOT / "docs" / "testing" / "mutation"
    rows = [json.loads(f.read_text(encoding="utf-8")) for f in sorted(d.glob("*.json")) if f.name != "summary.json"]
    for m in rows:
        m["killed"] = m.get("killed_with_failing_test_output", m["killed"])      # only kills that recorded a failing test count
        m.setdefault("complete", m["killed"] + m["survived"] + m["incompetent"])
        m.setdefault("round1", {"score_pct": m["score_pct"]})
    return rows


def mutation_totals(mut: list[dict]) -> dict:
    k, sv = sum(m["killed"] for m in mut), sum(m["survived"] for m in mut)
    k1, s1 = sum(m["round1"].get("killed", 0) for m in mut), sum(m["round1"].get("survived", 0) for m in mut)
    return {"killed": k, "survived": sv, "tested": sum(m["complete"] for m in mut), "incompetent": sum(m["incompetent"] for m in mut),
            "score": round(k / (k + sv) * 100, 1) if k + sv else None, "score_round1": round(k1 / (k1 + s1) * 100, 1) if k1 + s1 else None,
            "generated": sum(m.get("generated", 0) for m in mut), "annotation": sum(m.get("annotation_excluded", 0) for m in mut)}


__all__ = [n for n in dir() if not n.startswith("_")] + ["PageBreak", "Spacer", "KeepTogether"]
