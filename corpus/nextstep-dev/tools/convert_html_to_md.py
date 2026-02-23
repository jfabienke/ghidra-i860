#!/usr/bin/env python3
"""
HTML to Markdown Converter for NeXTSTEP Documentation

Converts HTML documentation (including .htmld directories) to well-formatted
Markdown suitable for both human reading and LLM consumption.

Usage:
    python3 convert_html_to_md.py input_dir output_dir [--preserve-structure]
"""

import argparse
import os
import sys
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
import json

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: BeautifulSoup not installed. Install with: pip install beautifulsoup4")
    sys.exit(1)

try:
    import html2text
    HAS_HTML2TEXT = True
except ImportError:
    HAS_HTML2TEXT = False
    print("Warning: html2text not installed. Using basic conversion.")
    print("For better quality: pip install html2text")


class HTMLToMarkdownConverter:
    def __init__(self, preserve_structure=True, extract_images=True):
        self.preserve_structure = preserve_structure
        self.extract_images = extract_images

        if HAS_HTML2TEXT:
            self.h2t = html2text.HTML2Text()
            self.h2t.body_width = 0  # Don't wrap lines
            self.h2t.ignore_links = False
            self.h2t.ignore_images = False
            self.h2t.skip_internal_links = False
            self.h2t.ignore_emphasis = False

    def extract_title(self, soup):
        """Extract document title"""
        # Try <title> tag
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            return title_tag.string.strip()

        # Try first <h1>
        h1_tag = soup.find('h1')
        if h1_tag:
            return h1_tag.get_text().strip()

        # Try first <h2>
        h2_tag = soup.find('h2')
        if h2_tag:
            return h2_tag.get_text().strip()

        return ""

    def extract_toc(self, soup):
        """Extract table of contents if present"""
        toc_links = []

        # Look for common TOC patterns
        for tag in soup.find_all(['nav', 'div'], class_=re.compile(r'toc|contents|navigation')):
            for link in tag.find_all('a'):
                href = link.get('href', '')
                text = link.get_text().strip()
                if text and href:
                    toc_links.append({'text': text, 'href': href})

        return toc_links

    def clean_html(self, soup):
        """Clean HTML by removing scripts, styles, etc."""
        # Remove script and style tags
        for tag in soup(['script', 'style', 'meta', 'link']):
            tag.decompose()

        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.startswith('<!--')):
            comment.extract()

        return soup

    def fix_code_blocks(self, soup):
        """Detect and mark code blocks properly"""
        # Find <pre> and <code> tags
        for pre in soup.find_all('pre'):
            # Check if it contains a <code> tag
            code = pre.find('code')
            if code:
                # Try to detect language
                classes = code.get('class', [])
                lang = ''
                for cls in classes:
                    if cls.startswith('language-'):
                        lang = cls.replace('language-', '')
                        break

                # Wrap in markdown code fence markers
                code.string = f"```{lang}\n{code.get_text()}\n```"
                code.unwrap()
                pre.unwrap()

    def process_links(self, soup, base_path):
        """Process and fix internal links"""
        for link in soup.find_all('a'):
            href = link.get('href', '')

            # Skip external links
            if href.startswith(('http://', 'https://', 'mailto:')):
                continue

            # Convert .html to .md
            if '.html' in href:
                href = re.sub(r'\.htmld?(/|$)', r'.md\1', href)
                href = href.replace('.html', '.md')
                link['href'] = href

            # Fix relative paths
            if href.startswith('../'):
                link['href'] = href

    def convert_html_to_md_basic(self, html):
        """Basic HTML to Markdown conversion"""
        soup = BeautifulSoup(html, 'html.parser')

        # Get text with some structure
        text = []
        for elem in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'pre', 'ul', 'ol']):
            if elem.name.startswith('h'):
                level = int(elem.name[1])
                text.append(f"\n{'#' * level} {elem.get_text().strip()}\n")
            elif elem.name == 'p':
                text.append(f"\n{elem.get_text().strip()}\n")
            elif elem.name == 'pre':
                text.append(f"\n```\n{elem.get_text()}\n```\n")
            elif elem.name in ('ul', 'ol'):
                for i, li in enumerate(elem.find_all('li', recursive=False)):
                    prefix = f"{i+1}." if elem.name == 'ol' else "-"
                    text.append(f"{prefix} {li.get_text().strip()}")

        return '\n'.join(text)

    def convert_html_to_md_html2text(self, html):
        """Convert HTML to Markdown using html2text"""
        return self.h2t.handle(html)

    def create_frontmatter(self, html_path, title, section=""):
        """Create YAML frontmatter"""
        frontmatter = [
            '---',
            f'title: "{title or html_path.stem}"',
            f'source: "{html_path.name}"',
            f'format: "HTML"',
        ]

        if section:
            frontmatter.append(f'section: "{section}"')

        frontmatter.append(f'converted: "{datetime.now().strftime("%Y-%m-%d")}"')
        frontmatter.append('---')
        frontmatter.append('')

        return '\n'.join(frontmatter)

    def convert_file(self, html_path, output_path, section=""):
        """Convert a single HTML file to Markdown"""
        print(f"  [CONV] {html_path.relative_to(html_path.parent.parent)}")

        try:
            # Read HTML
            html = html_path.read_text(encoding='utf-8', errors='ignore')

            # Parse with BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')

            # Extract metadata
            title = self.extract_title(soup)
            toc = self.extract_toc(soup)

            # Clean HTML
            soup = self.clean_html(soup)
            self.fix_code_blocks(soup)
            self.process_links(soup, html_path.parent)

            # Convert to Markdown
            if HAS_HTML2TEXT:
                md_content = self.convert_html_to_md_html2text(str(soup))
            else:
                md_content = self.convert_html_to_md_basic(str(soup))

            # Add TOC if present
            if toc:
                toc_md = ["## Table of Contents\n"]
                for item in toc:
                    toc_md.append(f"- [{item['text']}]({item['href']})")
                toc_md.append("\n---\n")
                md_content = '\n'.join(toc_md) + md_content

            # Create frontmatter
            frontmatter = self.create_frontmatter(html_path, title, section)

            # Write output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(frontmatter + '\n' + md_content, encoding='utf-8')

            print(f"  [OK] → {output_path.name}")
            return True

        except Exception as e:
            print(f"  [ERROR] Failed to convert {html_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def convert_directory(self, input_dir, output_dir):
        """Convert all HTML files in a directory"""
        input_path = Path(input_dir)
        output_path = Path(output_dir)

        if not input_path.exists():
            print(f"Error: Input directory not found: {input_dir}")
            return False

        # Find all HTML files
        html_files = []
        for pattern in ['*.html', '*.htm', '**/index.html']:
            html_files.extend(input_path.rglob(pattern))

        # Remove duplicates
        html_files = list(set(html_files))

        if not html_files:
            print(f"No HTML files found in {input_dir}")
            return False

        print(f"\nFound {len(html_files)} HTML files")
        print(f"Using: {'html2text' if HAS_HTML2TEXT else 'basic conversion'}")
        print()

        success = 0
        failed = 0

        for html_file in html_files:
            # Calculate relative path and determine section
            rel_path = html_file.relative_to(input_path)
            section = rel_path.parts[0] if rel_path.parts else ""

            # Handle .htmld directories (NeXTSTEP convention)
            if '.htmld' in str(rel_path):
                # Convert path/to/file.htmld/index.html → path/to/file.md
                rel_str = str(rel_path)
                if '/index.html' in rel_str:
                    rel_str = rel_str.replace('.htmld/index.html', '.md')
                elif '.htmld' in rel_str:
                    rel_str = rel_str.replace('.htmld', '.md')
                rel_path = Path(rel_str)

            md_path = output_path / rel_path.with_suffix('.md')

            if self.convert_file(html_file, md_path, section):
                success += 1
            else:
                failed += 1

        print(f"\n{'='*60}")
        print(f"Conversion Summary:")
        print(f"  Success: {success}")
        print(f"  Failed: {failed}")
        print(f"  Total: {len(html_files)}")

        return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="Convert HTML documentation to Markdown"
    )
    parser.add_argument(
        "input_dir",
        help="Input directory containing HTML files"
    )
    parser.add_argument(
        "output_dir",
        help="Output directory for Markdown files"
    )
    parser.add_argument(
        "--preserve-structure",
        action="store_true",
        default=True,
        help="Preserve directory structure (default: True)"
    )
    parser.add_argument(
        "--extract-images",
        action="store_true",
        default=True,
        help="Extract and save images (default: True)"
    )

    args = parser.parse_args()

    converter = HTMLToMarkdownConverter(
        preserve_structure=args.preserve_structure,
        extract_images=args.extract_images
    )
    success = converter.convert_directory(args.input_dir, args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
