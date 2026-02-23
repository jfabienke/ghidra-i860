#!/usr/bin/env python3
"""
NeXTSTEP 3.3 Developer Documentation Downloader

Downloads the complete NeXTSTEP 3.3 Developer Documentation from nextcomputers.org
and organizes it for conversion to Markdown.

Usage:
    python3 download_manuals.py [--sections SECTIONS] [--output-dir DIR]
"""

import argparse
import os
import sys
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import json

# Base URLs for NeXTSTEP documentation
BASE_URLS = [
    "https://www.nextcomputers.org/files/manuals/nd/",
    "https://www.nextcomputers.org/NeXTfiles/Docs/NeXTStep/3.3/nd/"
]

# Documentation sections
SECTIONS = {
    "Concepts": "Concepts - System architecture and programming concepts",
    "GeneralRef": "General Reference - API reference and specifications",
    "UserInterface": "User Interface - UI design guidelines",
    "ProgrammingTopics": "Programming Topics - Implementation guides",
    "ReleaseNotes": "Release Notes - Version-specific information",
    "Pre3.0_Concepts": "Pre-3.0 Concepts - Legacy documentation",
}

class NeXTDocDownloader:
    def __init__(self, output_dir, sections=None, delay=1.0):
        self.output_dir = Path(output_dir)
        self.sections = sections or list(SECTIONS.keys())
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })
        self.downloaded = set()
        self.failed = []

    def download_file(self, url, output_path):
        """Download a single file"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_path.exists():
                print(f"  [SKIP] {output_path.name} (already exists)")
                return True

            print(f"  [DOWN] {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            output_path.write_bytes(response.content)
            self.downloaded.add(str(output_path))
            time.sleep(self.delay)
            return True

        except Exception as e:
            print(f"  [FAIL] {url}: {e}")
            self.failed.append((url, str(e)))
            return False

    def parse_directory_listing(self, url):
        """Parse Apache/nginx directory listing"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            links = []
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and not href.startswith(('?', '/', 'http://', 'https://')):
                    links.append(href)

            return links

        except Exception as e:
            print(f"  [ERROR] Failed to parse {url}: {e}")
            return []

    def download_html_documentation(self, base_url, section):
        """Download HTML-based documentation"""
        print(f"\n[SECTION] {section} - {SECTIONS.get(section, '')}")
        section_url = urljoin(base_url, f"{section}/")
        section_dir = self.output_dir / section

        # Try to get directory listing
        items = self.parse_directory_listing(section_url)

        if not items:
            print(f"  [WARN] No items found, trying common patterns...")
            # Try common file patterns
            items = [
                "index.html",
                "index.htmld/index.html",
                "00_Introduction/Intro.htmld/index.html",
            ]

        for item in items:
            item_url = urljoin(section_url, item)

            if item.endswith('/'):
                # Recursively download subdirectory
                self.download_directory(item_url, section_dir / item.rstrip('/'))
            elif item.endswith(('.html', '.htmld', '.pdf', '.ps', '.rtf')):
                # Download file
                output_path = section_dir / item
                self.download_file(item_url, output_path)
            elif '.htmld' in item:
                # HTML directory - download index
                if not item.endswith('index.html'):
                    item_url = urljoin(item_url + '/', 'index.html')
                output_path = section_dir / item
                self.download_file(item_url, output_path)

    def download_directory(self, url, output_dir):
        """Recursively download a directory"""
        items = self.parse_directory_listing(url)

        for item in items:
            if item in ('.', '..', 'Parent Directory'):
                continue

            item_url = urljoin(url, item)

            if item.endswith('/'):
                self.download_directory(item_url, output_dir / item.rstrip('/'))
            else:
                output_path = output_dir / item
                self.download_file(item_url, output_path)

    def download_all(self):
        """Download all documentation"""
        print(f"NeXTSTEP 3.3 Developer Documentation Downloader")
        print(f"Output directory: {self.output_dir}")
        print(f"Sections: {', '.join(self.sections)}")
        print()

        # Try each base URL
        for base_url in BASE_URLS:
            print(f"[BASE] Trying {base_url}")

            for section in self.sections:
                try:
                    self.download_html_documentation(base_url, section)
                except Exception as e:
                    print(f"  [ERROR] Failed to download {section}: {e}")
                    continue

        # Summary
        print(f"\n{'='*60}")
        print(f"Download Summary:")
        print(f"  Downloaded: {len(self.downloaded)} files")
        print(f"  Failed: {len(self.failed)} files")

        if self.failed:
            print(f"\nFailed downloads:")
            for url, error in self.failed[:10]:  # Show first 10
                print(f"  - {url}")
                print(f"    {error}")

        # Save manifest
        manifest = {
            "downloaded": list(self.downloaded),
            "failed": self.failed,
            "sections": self.sections,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        manifest_path = self.output_dir / "download_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print(f"\nManifest saved to: {manifest_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Download NeXTSTEP 3.3 Developer Documentation"
    )
    parser.add_argument(
        "--sections",
        help=f"Comma-separated list of sections to download. Available: {', '.join(SECTIONS.keys())}",
        default=None
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory for downloaded files",
        default="./downloads"
    )
    parser.add_argument(
        "--delay",
        type=float,
        help="Delay between requests in seconds (default: 1.0)",
        default=1.0
    )

    args = parser.parse_args()

    # Parse sections
    sections = None
    if args.sections:
        sections = [s.strip() for s in args.sections.split(',')]
        invalid = [s for s in sections if s not in SECTIONS]
        if invalid:
            print(f"Error: Invalid sections: {', '.join(invalid)}")
            print(f"Available: {', '.join(SECTIONS.keys())}")
            return 1

    # Create downloader and run
    downloader = NeXTDocDownloader(
        output_dir=args.output_dir,
        sections=sections,
        delay=args.delay
    )

    try:
        downloader.download_all()
        return 0
    except KeyboardInterrupt:
        print("\n\nDownload interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
