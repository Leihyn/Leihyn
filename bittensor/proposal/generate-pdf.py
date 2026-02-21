"""Convert VIGIL-FINAL.md to a polished PDF via styled HTML + Chrome headless,
then stamp logo + page numbers on every page."""
import markdown
import subprocess
import os
import base64
import re
from io import BytesIO

INPUT = "VIGIL-FINAL.md"
LOGO = "vigil-logo-new.jpg"
HTML_OUT = "Vigil-Subnet-Proposal.html"
PDF_RAW = "Vigil-Subnet-Proposal-raw.pdf"
PDF_OUT = "Vigil-Subnet-Proposal.pdf"

# --- Step 1: Convert Markdown to styled HTML ---

with open(INPUT, "r") as f:
    md_content = f.read()

html_body = markdown.markdown(
    md_content,
    extensions=["tables", "fenced_code", "toc"],
)

html_doc = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vigil: Decentralized Liquidation Prediction - Subnet Proposal</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

@page {{
    size: A4;
    margin: 2.8cm 2cm 2.5cm 2cm;
}}

body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 11pt;
    line-height: 1.65;
    color: #1a1a2e;
    max-width: 100%;
    margin: 0;
    padding: 0;
}}

h1 {{
    font-size: 26pt;
    font-weight: 800;
    color: #0a1628;
    border-bottom: 3px solid #c9a962;
    padding-bottom: 12px;
    margin-top: 0;
    margin-bottom: 24px;
}}

h2 {{
    font-size: 17pt;
    font-weight: 700;
    color: #0d1f3c;
    border-bottom: 2px solid #e8d5a3;
    padding-bottom: 6px;
    margin-top: 36px;
    margin-bottom: 16px;
    page-break-after: avoid;
}}

h3 {{
    font-size: 12.5pt;
    font-weight: 700;
    color: #1a3a5c;
    margin-top: 24px;
    margin-bottom: 10px;
    page-break-after: avoid;
}}

p {{
    margin-bottom: 10px;
}}

strong {{
    color: #0a1628;
}}

hr {{
    border: none;
    border-top: 1px solid #ddd;
    margin: 28px 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin: 14px 0;
    font-size: 9.5pt;
    page-break-inside: avoid;
}}

thead tr {{
    background: #0d1f3c;
}}

th {{
    padding: 9px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 9.5pt;
    color: #ffffff;
}}

td {{
    padding: 7px 12px;
    border-bottom: 1px solid #e0e0e0;
    vertical-align: top;
}}

tr:nth-child(even) td {{
    background: #f8f8fa;
}}

code {{
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 9pt;
    background: #f0f0f5;
    padding: 1px 5px;
    border-radius: 3px;
    color: #8b6914;
}}

pre {{
    background: #0d1f3c;
    color: #e8d5a3;
    padding: 14px 18px;
    border-radius: 8px;
    font-size: 8.5pt;
    line-height: 1.5;
    overflow-x: auto;
    page-break-inside: avoid;
    margin: 14px 0;
}}

pre code {{
    background: none;
    padding: 0;
    color: #e8d5a3;
    font-size: 8.5pt;
}}

ul, ol {{
    margin-bottom: 10px;
    padding-left: 22px;
}}

li {{
    margin-bottom: 4px;
}}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

with open(HTML_OUT, "w") as f:
    f.write(html_doc)
print(f"Generated {HTML_OUT}")

# --- Step 2: Render to raw PDF with Chrome headless ---

chrome_paths = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]

chrome = None
for p in chrome_paths:
    if os.path.exists(p):
        chrome = p
        break

if not chrome:
    print("Chrome not found. Cannot generate PDF.")
    exit(1)

html_path = os.path.abspath(HTML_OUT)
raw_pdf_path = os.path.abspath(PDF_RAW)

result = subprocess.run([
    chrome,
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    f"--print-to-pdf={raw_pdf_path}",
    "--no-pdf-header-footer",
    f"file://{html_path}",
], capture_output=True, text=True, timeout=30)

if not os.path.exists(raw_pdf_path):
    print(f"Chrome error: {result.stderr}")
    exit(1)

print(f"Generated raw PDF")

# --- Step 3: Stamp logo + page numbers on every page ---

from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

reader = PdfReader(raw_pdf_path)
writer = PdfWriter()
total_pages = len(reader.pages)
logo_path = os.path.abspath(LOGO)

print(f"Stamping logo + page numbers on {total_pages} pages...")

for i, page in enumerate(reader.pages):
    page_num = i + 1
    page_width = float(page.mediabox.width)
    page_height = float(page.mediabox.height)

    # Create overlay with logo + page number
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_width, page_height))

    # Draw logo top-right corner (40x40, with some margin)
    logo_size = 36
    logo_x = page_width - logo_size - 45  # 45pt from right edge
    logo_y = page_height - logo_size - 38  # 38pt from top edge
    c.drawImage(
        ImageReader(logo_path),
        logo_x, logo_y,
        width=logo_size, height=logo_size,
        mask="auto",
    )

    # Draw page number bottom-center
    c.setFont("Helvetica", 9)
    c.setFillColorRGB(0.55, 0.55, 0.55)  # gray
    c.drawCentredString(page_width / 2, 30, f"{page_num} / {total_pages}")

    c.save()
    buf.seek(0)

    # Merge overlay onto page
    overlay_reader = PdfReader(buf)
    page.merge_page(overlay_reader.pages[0])
    writer.add_page(page)

# Write final PDF
final_path = os.path.abspath(PDF_OUT)
with open(final_path, "wb") as f:
    writer.write(f)

# Clean up raw PDF
os.remove(raw_pdf_path)

size_kb = os.path.getsize(final_path) / 1024
print(f"Generated {PDF_OUT} ({size_kb:.0f} KB) - {total_pages} pages with logo + page numbers")
