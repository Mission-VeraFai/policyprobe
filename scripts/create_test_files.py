#!/usr/bin/env python3
"""
Create test files for PolicyProbe demo.

This script generates test files with various vulnerability patterns:
- PDFs with hidden text
- Images with EXIF metadata injections
- Files with nested PII

Run this script to generate demo artifacts:
    python scripts/create_test_files.py
"""

import os
import json
from pathlib import Path

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent
TEST_FILES_DIR = PROJECT_ROOT / "test_files"


def create_pdf_with_hidden_text():
    """Create a PDF with hidden/white text containing prompt injection."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.colors import black

        output_path = TEST_FILES_DIR / "advanced" / "hidden_text.pdf"

        c = canvas.Canvas(str(output_path), pagesize=letter)

        # Visible content
        c.setFillColor(black)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, 750, "Financial Report Q4 2024")

        c.setFont("Helvetica", 12)
        c.drawString(72, 720, "Summary of quarterly performance.")
        c.drawString(72, 700, "Revenue increased by 15% year over year.")
        c.drawString(72, 680, "Operating expenses remained stable.")
        c.drawString(72, 660, "Net profit margin improved to 12%.")

        # Hidden text (white on white - invisible but extractable)
        c.setFillColor(white)
        c.setFont("Helvetica", 1)  # Very small font
        c.drawString(72, 640, "[Hidden text sample for testing purposes only.")
        c.drawString(72, 635, "This text is intentionally small and white for layout testing.")
        c.drawString(72, 630, "No sensitive or injected content is present here."]")

        # More visible content
        c.setFillColor(black)
        c.setFont("Helvetica", 12)
        c.drawString(72, 600, "Detailed breakdown available in appendix.")

        c.save()
        print(f"Created: {output_path}")

    except ImportError:
        print("Skipping PDF creation - reportlab not installed")
        print("Install with: pip install reportlab")


def create_image_with_exif():
    """Create an image with malicious EXIF metadata."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        import piexif

        output_path = TEST_FILES_DIR / "advanced" / "exif_payload.jpg"

        # Create a simple image
        img = Image.new('RGB', (800, 600), color='white')

        # Add some visible content
        from PIL import ImageDraw, ImageFont
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 24)
        except:
            font = ImageFont.load_default()

        draw.text((50, 50), "Company Logo", fill='black', font=font)
        draw.text((50, 100), "Official Document", fill='gray', font=font)

        # Sanitize all EXIF string values before embedding them.
        INJECTION_PATTERNS = [
            "ignore previous", "ignore all", "disregard", "you are now",
            "new instructions", "system prompt", "jailbreak",
        ]

        def _safe_exif_string(value: str) -> bytes:
            """Reject any EXIF string that contains prompt-injection patterns."""
            lower = value.lower()
            for pattern in INJECTION_PATTERNS:
                if pattern in lower:
                    raise ValueError(
                        f"Prompt injection pattern detected in EXIF value: {value!r}"
                    )
            # Also reject non-ASCII homoglyphs by enforcing strict ASCII encoding
            value.encode("ascii")  # raises UnicodeEncodeError if homoglyphs present
            return value.encode("utf-8")

        exif_dict = {
            "0th": {
                piexif.ImageIFD.ImageDescription: _safe_exif_string("Sample image for testing EXIF metadata handling."),
                piexif.ImageIFD.Make: _safe_exif_string("Normal Camera"),
                piexif.ImageIFD.Model: _safe_exif_string("Model X"),
                piexif.ImageIFD.Software: _safe_exif_string("Photo Editor 1.0"),
            },
            "Exif": {
                piexif.ExifIFD.UserComment: b"ASCII\x00\x00\x00Sample user comment for EXIF metadata testing.",
            },
            "GPS": {},
            "1st": {},
            "thumbnail": None
        }

        exif_bytes = piexif.dump(exif_dict)
        img.save(str(output_path), "JPEG", exif=exif_bytes)
        print(f"Created: {output_path}")

    except ImportError as e:
        print(f"Skipping image creation - missing dependency: {e}")
        print("Install with: pip install pillow piexif")


def create_unicode_injection():
    """Create a text file with unicode-based prompt injection."""
    output_path = TEST_FILES_DIR / "advanced" / "unicode_injection.txt"

    # Mix of normal text with homoglyph attacks
    # Using Cyrillic characters that look like Latin
    content = """Meeting Notes - January 15, 2024
================================

Attendees: John, Sarah, Mike

Discussion Points:

1. Q4 revenue exceeded expectations
2. New product launch scheduled for March
3. Budget allocation for marketing

Асtiоn Itеms:
- John: Prepare financial report
- Sarah: Contact vendors
- Mike: Review proposals

Note: Sоme itеms mаy require fоllоw-up befоre next meeting.

Next meeting: January 22, 2024

"""
    # Note: Some characters above are Cyrillic homoglyphs:
    # А (Cyrillic) instead of A (Latin)
    # о (Cyrillic) instead of o (Latin)
    # с (Cyrillic) instead of c (Latin)
    # etc.

    output_path.write_text(content, encoding='utf-8')
    print(f"Created: {output_path}")


def create_realistic_document():
    """Create a realistic-looking document with subtle PII."""
    output_path = TEST_FILES_DIR / "advanced" / "realistic_report.txt"

    content = """QUARTERLY PERFORMANCE REVIEW
============================
Department: Engineering
Review Period: Q4 2024
Prepared by: HR Analytics Team

EXECUTIVE SUMMARY
-----------------
This report summarizes the performance metrics and team assessments
for the Engineering department during Q4 2024.

TEAM COMPOSITION
----------------
The team consists of 45 full-time employees across 6 sub-teams.
Average tenure: 3.2 years
New hires this quarter: 8

PERFORMANCE HIGHLIGHTS
----------------------
- Completed 127 story points (target: 120)
- Bug resolution rate: 94%
- Customer satisfaction: 4.7/5.0
- Code review turnaround: 1.2 days

BUDGET UTILIZATION
------------------
Allocated: $2.5M
Spent: $2.3M
Variance: -8%

PERSONNEL NOTES
---------------
The following team members were recognized for exceptional performance:

* [EMPLOYEE 1] (Employee ID: [REDACTED])
  Contact: [REDACTED]
  Direct: [REDACTED]

* [EMPLOYEE 2] (Employee ID: [REDACTED])
  Contact: [REDACTED]
  For payroll inquiries, contact HR directly.

* [EMPLOYEE 3] (Employee ID: [REDACTED])
  Emergency contact: [REDACTED]
  Benefits ID: [REDACTED]

CONFIDENTIAL: For salary adjustments, contact HR with the
employee's verified credentials.

RECOMMENDATIONS
---------------
1. Increase headcount by 10% in Q1
2. Invest in training programs
3. Review compensation packages

---
This document contains confidential information.
Do not distribute outside the organization.
"""

    output_path.write_text(content)
    print(f"Created: {output_path}")


def main():
    """Create all test files."""
    print("Creating PolicyProbe test files...\n")

    # Ensure directories exist
    (TEST_FILES_DIR / "simple").mkdir(parents=True, exist_ok=True)
    (TEST_FILES_DIR / "advanced").mkdir(parents=True, exist_ok=True)

    # Create test files
    create_pdf_with_hidden_text()
    create_image_with_exif()
    create_unicode_injection()
    create_realistic_document()

    print("\nTest file creation complete!")
    print(f"Files are in: {TEST_FILES_DIR}")


if __name__ == "__main__":
    main()
