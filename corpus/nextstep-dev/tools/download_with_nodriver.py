#!/usr/bin/env python3
"""
NeXTSTEP Documentation Downloader with Cloudflare Bypass

Uses nodriver to bypass Cloudflare protection that blocks standard HTTP requests.
This is the recommended method for downloading from nextcomputers.org in 2024-2025.

Usage:
    python3 download_with_nodriver.py [--output-dir DIR] [--sections SECTIONS]

Requirements:
    pip install nodriver
"""

import asyncio
import sys
import argparse
import json
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from datetime import datetime

try:
    import nodriver as uc
except ImportError:
    print("Error: nodriver not installed")
    print("Install with: pip install nodriver")
    sys.exit(1)


# Documentation sections
SECTIONS = {
    "Concepts": "System architecture and programming concepts",
    "GeneralRef": "API reference and specifications",
    "UserInterface": "UI design guidelines",
    "ProgrammingTopics": "Implementation guides",
    "ReleaseNotes": "Version-specific information",
    "Pre3.0_Concepts": "Legacy documentation",
}


class NodriverDownloader:
    def __init__(self, output_dir, sections=None, headless=False):
        self.output_dir = Path(output_dir)
        self.sections = sections or list(SECTIONS.keys())
        self.headless = headless
        self.downloaded = set()
        self.failed = []
        self.browser = None

    async def start_browser(self):
        """Start the browser instance"""
        print(f"Starting browser (headless={self.headless})...")
        self.browser = await uc.start(headless=self.headless)
        print("Browser started successfully")

    async def stop_browser(self):
        """Stop the browser instance"""
        if self.browser:
            await self.browser.stop()
            print("Browser stopped")

    async def wait_for_cloudflare(self, page, max_wait=30):
        """Wait for Cloudflare challenge to complete"""
        start_time = time.time()

        while time.time() - start_time < max_wait:
            try:
                title = await page.evaluate("document.title")

                # Check for Cloudflare challenge page
                if "Just a moment" in title or "Cloudflare" in title:
                    print(f"  [WAIT] Cloudflare challenge detected...")
                    await asyncio.sleep(2)
                    continue

                # Check if we have content
                body = await page.evaluate("document.body ? document.body.innerText.length : 0")
                if body > 100:  # Arbitrary threshold
                    print(f"  [PASS] Cloudflare bypass successful")
                    return True

            except Exception as e:
                print(f"  [DEBUG] Error checking page: {e}")

            await asyncio.sleep(1)

        print(f"  [TIMEOUT] Cloudflare challenge timeout after {max_wait}s")
        return False

    async def download_page(self, url, output_path):
        """Download a single page"""
        try:
            print(f"  [FETCH] {url}")

            # Navigate to page
            page = await self.browser.get(url, new_tab=False)

            # Wait for Cloudflare
            if not await self.wait_for_cloudflare(page):
                self.failed.append((url, "Cloudflare timeout"))
                return False

            # Additional wait for dynamic content
            await asyncio.sleep(2)

            # Get page content
            content = await page.get_content()

            if not content or len(content) < 500:
                print(f"  [WARN] Suspiciously small content ({len(content)} bytes)")

            # Save to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding='utf-8')

            self.downloaded.add(str(output_path))
            print(f"  [SAVE] {output_path.name} ({len(content)} bytes)")

            # Be polite - random delay between requests
            delay = 2 + (hash(url) % 3)  # 2-4 seconds
            await asyncio.sleep(delay)

            return True

        except Exception as e:
            print(f"  [ERROR] Failed to download {url}: {e}")
            self.failed.append((url, str(e)))
            return False

    async def discover_links(self, url):
        """Discover links on a page (for recursive download)"""
        try:
            page = await self.browser.get(url, new_tab=False)
            await self.wait_for_cloudflare(page)

            # Get all links
            links = await page.evaluate("""
                Array.from(document.querySelectorAll('a')).map(a => a.href)
            """)

            # Filter for documentation links
            doc_links = []
            for link in links:
                if '.htmld' in link or link.endswith('.html'):
                    if 'manuals/nd/' in link:
                        doc_links.append(link)

            return doc_links

        except Exception as e:
            print(f"  [ERROR] Failed to discover links: {e}")
            return []

    async def download_section(self, base_url, section):
        """Download a documentation section"""
        print(f"\n{'='*60}")
        print(f"[SECTION] {section} - {SECTIONS.get(section, '')}")
        print(f"{'='*60}\n")

        section_url = urljoin(base_url, section + '/')
        section_dir = self.output_dir / section

        # Download section index
        index_path = section_dir / "index.html"
        await self.download_page(section_url, index_path)

        # Try common documentation patterns
        common_pages = [
            "00_Introduction/Intro.htmld/index.html",
            "01_Overview/Overview.htmld/index.html",
            "index.htmld/index.html",
        ]

        for page in common_pages:
            page_url = urljoin(section_url, page)
            page_path = section_dir / page
            await self.download_page(page_url, page_path)

        # Optional: Discover and download linked pages
        # This could be enabled for more complete downloads
        # links = await self.discover_links(section_url)
        # for link in links[:10]:  # Limit for testing
        #     ...

    async def download_all(self, base_url):
        """Download all documentation sections"""
        print(f"NeXTSTEP Documentation Downloader (Nodriver)")
        print(f"Output directory: {self.output_dir}")
        print(f"Sections: {', '.join(self.sections)}")
        print()

        await self.start_browser()

        try:
            for section in self.sections:
                await self.download_section(base_url, section)

        finally:
            await self.stop_browser()

        # Summary
        print(f"\n{'='*60}")
        print(f"Download Summary:")
        print(f"  Downloaded: {len(self.downloaded)} files")
        print(f"  Failed: {len(self.failed)} files")
        print(f"{'='*60}")

        if self.failed:
            print(f"\nFailed downloads:")
            for url, error in self.failed[:10]:
                print(f"  - {url}")
                print(f"    {error}")

        # Save manifest
        manifest = {
            "downloaded": list(self.downloaded),
            "failed": self.failed,
            "sections": self.sections,
            "timestamp": datetime.now().isoformat(),
            "method": "nodriver"
        }

        manifest_path = self.output_dir / "download_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print(f"\nManifest saved to: {manifest_path}")


async def main():
    parser = argparse.ArgumentParser(
        description="Download NeXTSTEP documentation with Cloudflare bypass"
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory for downloaded files",
        default="./downloads"
    )
    parser.add_argument(
        "--sections",
        help=f"Comma-separated list of sections. Available: {', '.join(SECTIONS.keys())}",
        default=None
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run browser in headless mode (less reliable but faster)"
    )
    parser.add_argument(
        "--base-url",
        help="Base URL for documentation",
        default="https://www.nextcomputers.org/files/manuals/nd/"
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

    # Create downloader
    downloader = NodriverDownloader(
        output_dir=args.output_dir,
        sections=sections,
        headless=args.headless
    )

    try:
        await downloader.download_all(args.base_url)
        return 0

    except KeyboardInterrupt:
        print("\n\nDownload interrupted by user")
        return 1

    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
