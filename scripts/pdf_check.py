"""Open a PDF, report page count/size, extract text sanity info and render selected pages to PNG for visual checks."""
import sys
from pathlib import Path

import fitz  # PyMuPDF

pdf = Path(sys.argv[1])
pages = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else []
doc = fitz.open(pdf)
print(f"{pdf.name}: {doc.page_count} pages, {pdf.stat().st_size // 1024} KB, title={doc.metadata.get('title')!r}")
empty = [i + 1 for i, pg in enumerate(doc) if len(pg.get_text().strip()) < 20 and not pg.get_images()]
print("pages without text or images:", empty or "none")
# clipping check: any image or text block that extends beyond the page margins
rect = doc[0].rect
bad = []
for i, pg in enumerate(doc):
    for b in pg.get_text("blocks"):
        if b[2] > rect.width + 1 or b[0] < -1 or b[3] > rect.height + 1:
            bad.append((i + 1, [round(v) for v in b[:4]]))
print("text blocks outside the page:", bad[:5] or "none")
out = Path(".tmp/pdfpages"); out.mkdir(parents=True, exist_ok=True)
for n in pages:
    doc[n - 1].get_pixmap(dpi=70).save(out / f"{pdf.stem[:12]}_{n:03d}.png")
    print("rendered", n)
