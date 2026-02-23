#!/usr/bin/env python3
"""
PDF to Markdown Converter for NeXTSTEP Documentation

Converts PDF documentation to well-formatted Markdown suitable for both
human reading and LLM consumption.

Usage:
    python3 convert_pdf_to_md.py input_dir output_dir [--quality high]
"""

import argparse
import os
import sys
import re
from pathlib import Path
from datetime import datetime
import json

try:
    import PyPDF2
    from PyPDF2 import PdfReader
except ImportError:
    print("Error: PyPDF2 not installed. Install with: pip install PyPDF2")
    sys.exit(1)

try:
    import pdfplumber
    HAS_PDFPLUMBER = True
except ImportError:
    HAS_PDFPLUMBER = False
    print("Warning: pdfplumber not installed. Using PyPDF2 only.")
    print("For better quality: pip install pdfplumber")


class PDFToMarkdownConverter:
    def __init__(self, quality='medium'):
        self.quality = quality
        self.use_pdfplumber = HAS_PDFPLUMBER and quality in ('high', 'medium')

    def extract_metadata(self, pdf_path):
        """Extract PDF metadata"""
        try:
            reader = PdfReader(pdf_path)
            info = reader.metadata

            return {
                'title': info.get('/Title', ''),
                'author': info.get('/Author', ''),
                'subject': info.get('/Subject', ''),
                'creator': info.get('/Creator', ''),
                'producer': info.get('/Producer', ''),
                'pages': len(reader.pages)
            }
        except Exception as e:
            print(f"  [WARN] Failed to extract metadata: {e}")
            return {}

    def extract_text_pypdf2(self, pdf_path):
        """Extract text using PyPDF2 (fallback)"""
        try:
            reader = PdfReader(pdf_path)
            text = []

            for page_num, page in enumerate(reader.pages, 1):
                page_text = page.extract_text()
                if page_text.strip():
                    text.append(f"\n<!-- Page {page_num} -->\n")
                    text.append(page_text)

            return '\n'.join(text)
        except Exception as e:
            print(f"  [ERROR] PyPDF2 extraction failed: {e}")
            return ""

    def extract_text_pdfplumber(self, pdf_path):
        """Extract text using pdfplumber (better quality)"""
        try:
            text = []

            with pdfplumber.open(pdf_path) as pdf:
                for page_num, page in enumerate(pdf.pages, 1):
                    # Extract text
                    page_text = page.extract_text()
                    if page_text and page_text.strip():
                        text.append(f"\n<!-- Page {page_num} -->\n")
                        text.append(page_text)

                    # Extract tables
                    tables = page.extract_tables()
                    if tables:
                        for table in tables:
                            text.append(self.format_table(table))

            return '\n'.join(text)
        except Exception as e:
            print(f"  [ERROR] pdfplumber extraction failed: {e}")
            return ""

    def format_table(self, table):
        """Convert table to Markdown format"""
        if not table or len(table) < 2:
            return ""

        md_table = []

        # Header row
        header = [cell or '' for cell in table[0]]
        md_table.append('| ' + ' | '.join(header) + ' |')

        # Separator
        md_table.append('| ' + ' | '.join(['---'] * len(header)) + ' |')

        # Data rows
        for row in table[1:]:
            cells = [cell or '' for cell in row]
            # Pad to header length
            cells += [''] * (len(header) - len(cells))
            md_table.append('| ' + ' | '.join(cells[:len(header)]) + ' |')

        return '\n' + '\n'.join(md_table) + '\n'

    def clean_text(self, text):
        """Clean and normalize extracted text"""
        # Remove form feed characters
        text = text.replace('\f', '\n')

        # Normalize line endings
        text = text.replace('\r\n', '\n').replace('\r', '\n')

        # Remove excessive blank lines (more than 2)
        text = re.sub(r'\n{3,}', '\n\n', text)

        # Fix common OCR issues
        text = text.replace('ﬁ', 'fi').replace('ﬂ', 'fl')

        return text

    def detect_structure(self, text):
        """Detect document structure and add Markdown formatting"""
        lines = text.split('\n')
        formatted = []

        in_code_block = False
        prev_line_blank = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Preserve page markers
            if stripped.startswith('<!-- Page'):
                formatted.append(line)
                continue

            # Detect code blocks (indented lines or certain patterns)
            if line.startswith('    ') or line.startswith('\t'):
                if not in_code_block:
                    formatted.append('```')
                    in_code_block = True
                formatted.append(line[4:] if line.startswith('    ') else line[1:])
                continue
            elif in_code_block:
                formatted.append('```')
                in_code_block = False

            # Detect headers (ALL CAPS lines, or lines ending with specific patterns)
            if stripped and stripped.isupper() and len(stripped) > 3:
                # Determine header level based on context
                if prev_line_blank or i == 0:
                    formatted.append(f"\n## {stripped}\n")
                    prev_line_blank = False
                    continue

            # Detect numbered/bulleted lists
            if re.match(r'^[\d\•\-\*]\s+', stripped):
                formatted.append(line)
                prev_line_blank = False
                continue

            # Regular line
            if stripped:
                formatted.append(line)
                prev_line_blank = False
            else:
                formatted.append('')
                prev_line_blank = True

        if in_code_block:
            formatted.append('```')

        return '\n'.join(formatted)

    def create_frontmatter(self, pdf_path, metadata):
        """Create YAML frontmatter"""
        frontmatter = [
            '---',
            f'title: "{metadata.get("title", pdf_path.stem)}"',
            f'source: "{pdf_path.name}"',
            f'format: "PDF"',
        ]

        if metadata.get('author'):
            frontmatter.append(f'author: "{metadata["author"]}"')

        if metadata.get('subject'):
            frontmatter.append(f'subject: "{metadata["subject"]}"')

        frontmatter.append(f'pages: {metadata.get("pages", "unknown")}')
        frontmatter.append(f'converted: "{datetime.now().strftime("%Y-%m-%d")}"')
        frontmatter.append('---')
        frontmatter.append('')

        return '\n'.join(frontmatter)

    def convert_file(self, pdf_path, output_path):
        """Convert a single PDF file to Markdown"""
        print(f"  [CONV] {pdf_path.name}")

        try:
            # Extract metadata
            metadata = self.extract_metadata(pdf_path)

            # Extract text
            if self.use_pdfplumber:
                text = self.extract_text_pdfplumber(pdf_path)
                if not text:
                    print(f"  [WARN] pdfplumber failed, falling back to PyPDF2")
                    text = self.extract_text_pypdf2(pdf_path)
            else:
                text = self.extract_text_pypdf2(pdf_path)

            if not text or not text.strip():
                print(f"  [WARN] No text extracted from {pdf_path.name}")
                return False

            # Clean and structure
            text = self.clean_text(text)
            text = self.detect_structure(text)

            # Create frontmatter
            frontmatter = self.create_frontmatter(pdf_path, metadata)

            # Write output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(frontmatter + '\n' + text, encoding='utf-8')

            print(f"  [OK] → {output_path.name}")
            return True

        except Exception as e:
            print(f"  [ERROR] Failed to convert {pdf_path.name}: {e}")
            return False

    def convert_directory(self, input_dir, output_dir):
        """Convert all PDFs in a directory"""
        input_path = Path(input_dir)
        output_path = Path(output_dir)

        if not input_path.exists():
            print(f"Error: Input directory not found: {input_dir}")
            return False

        # Find all PDFs
        pdf_files = list(input_path.rglob('*.pdf'))

        if not pdf_files:
            print(f"No PDF files found in {input_dir}")
            return False

        print(f"\nFound {len(pdf_files)} PDF files")
        print(f"Quality: {self.quality}")
        print(f"Using: {'pdfplumber' if self.use_pdfplumber else 'PyPDF2'}")
        print()

        success = 0
        failed = 0

        for pdf_file in pdf_files:
            # Calculate relative path
            rel_path = pdf_file.relative_to(input_path)
            md_path = output_path / rel_path.with_suffix('.md')

            if self.convert_file(pdf_file, md_path):
                success += 1
            else:
                failed += 1

        print(f"\n{'='*60}")
        print(f"Conversion Summary:")
        print(f"  Success: {success}")
        print(f"  Failed: {failed}")
        print(f"  Total: {len(pdf_files)}")

        return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="Convert PDF documentation to Markdown"
    )
    parser.add_argument(
        "input_dir",
        help="Input directory containing PDFs"
    )
    parser.add_argument(
        "output_dir",
        help="Output directory for Markdown files"
    )
    parser.add_argument(
        "--quality",
        choices=['low', 'medium', 'high'],
        default='medium',
        help="Conversion quality (high requires pdfplumber)"
    )

    args = parser.parse_args()

    converter = PDFToMarkdownConverter(quality=args.quality)
    success = converter.convert_directory(args.input_dir, args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
