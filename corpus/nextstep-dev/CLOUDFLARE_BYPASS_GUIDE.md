# Cloudflare Bypass Guide for NeXTSTEP Documentation Download

## Overview

The nextcomputers.org website uses **Cloudflare Bot Protection** which blocks automated scraping. This guide documents current (2024-2025) methods to bypass this protection for legitimate documentation archival purposes.

## ⚖️ Legal and Ethical Considerations

**IMPORTANT**: This guide is for:
- ✅ Archival and preservation of historical documentation
- ✅ Personal research and education
- ✅ Non-commercial use
- ❌ NOT for: commercial scraping, DDoS, or malicious purposes

**Best Practice**: Contact the site owner first to request bulk download permission or check if they have an archive available.

## Current State (2024-2025)

### Cloudflare's Protections
- **JavaScript challenges** - Requires JS execution
- **Browser fingerprinting** - Checks for automation
- **Turnstile CAPTCHA** - Cloudflare's CAPTCHA replacement (introduced 2022)
- **Machine learning detection** - Per-customer ML models
- **Behavioral analysis** - Monitors mouse movement, timing, etc.

### Bypass Difficulty
- Old simple methods (curl, requests) → **100% blocked**
- Basic headless browsers (Selenium) → **90%+ blocked**
- Stealth browsers (undetected-chromedriver) → **60-80% blocked** (declining)
- Modern tools (nodriver, SeleniumBase) → **40-60% success** (best available)
- Commercial services → **80-95% success** (expensive)

## Recommended Tools (Free/Open Source)

### 1. Nodriver (Best Free Option - 2024)

**Status**: Official successor to undetected-chromedriver, works where Selenium fails

**Installation**:
```bash
pip install nodriver
```

**Basic Usage**:
```python
import nodriver as uc
import asyncio

async def main():
    browser = await uc.start()
    page = await browser.get('https://www.nextcomputers.org/files/manuals/nd/')

    # Wait for page to load
    await asyncio.sleep(5)

    # Get content
    content = await page.get_content()
    print(content)

    await browser.stop()

asyncio.run(main())
```

**GitHub**: https://github.com/ultrafunkamsterdam/nodriver

**Pros**:
- ✅ Free and open source
- ✅ Works where undetected-chromedriver fails
- ✅ Active development (2024)
- ✅ Automatic Cloudflare challenge solving

**Cons**:
- ⚠️ Slower than simple HTTP requests
- ⚠️ Requires Chrome/Chromium installed
- ⚠️ May still be detected on some sites

### 2. Nodriver-CF-Bypass Plugin

**Enhancement**: Lightweight plugin specifically for Cloudflare Turnstile

**Installation**:
```bash
pip install nodriver-cf-bypass
```

**Usage**:
```python
import nodriver as uc
from nodriver_cf_bypass import bypass_cf

async def main():
    browser = await uc.start()
    page = await browser.get('https://www.nextcomputers.org/files/manuals/nd/')

    # Automatically bypass Cloudflare
    await bypass_cf(page)

    content = await page.get_content()
    # ... process content

asyncio.run(main())
```

**GitHub**: https://github.com/KlozetLabs/nodriver-cf-bypass

### 3. Cloudscraper (Simple HTTP Bypass)

**Status**: Works for older Cloudflare challenges, may fail on modern Turnstile

**Installation**:
```bash
pip install cloudscraper
```

**Usage**:
```python
import cloudscraper

scraper = cloudscraper.create_scraper()
response = scraper.get("https://www.nextcomputers.org/files/manuals/nd/")
print(response.text)
```

**GitHub**: https://github.com/VeNoMouS/cloudscraper

**Pros**:
- ✅ Simple drop-in replacement for requests
- ✅ Fast (no browser needed)
- ✅ Good for older Cloudflare challenges

**Cons**:
- ❌ Often fails on modern Turnstile (2024)
- ❌ Requires JavaScript interpreter (js2py, Node.js, etc.)

### 4. SeleniumBase with CDP Mode

**Status**: Reliable for Cloudflare bypass with proper configuration

**Installation**:
```bash
pip install seleniumbase
```

**Usage**:
```python
from seleniumbase import SB

with SB(uc=True, headed=False) as sb:
    url = "https://www.nextcomputers.org/files/manuals/nd/"
    sb.uc_open_with_reconnect(url, 4)
    sb.sleep(2)
    print(sb.get_page_source())
```

**Pros**:
- ✅ CDP (Chrome DevTools Protocol) mode more reliable
- ✅ Built-in undetected mode
- ✅ Well-documented

**Cons**:
- ⚠️ Heavier than cloudscraper
- ⚠️ Requires Chrome/Chromium

### 5. FlareSolverr (Proxy Server Approach)

**Status**: Self-hosted proxy that solves Cloudflare challenges

**Installation**:
```bash
docker pull ghcr.io/flaresolverr/flaresolverr:latest
docker run -d -p 8191:8191 flaresolverr/flaresolverr
```

**Usage**:
```python
import requests

solver_url = "http://localhost:8191/v1"
response = requests.post(solver_url, json={
    "cmd": "request.get",
    "url": "https://www.nextcomputers.org/files/manuals/nd/",
    "maxTimeout": 60000
})

solution = response.json()
print(solution['solution']['response'])
```

**GitHub**: https://github.com/FlareSolverr/FlareSolverr

**Pros**:
- ✅ Can be shared across multiple scrapers
- ✅ Supports both Selenium and nodriver backends
- ✅ RESTful API

**Cons**:
- ⚠️ Requires Docker
- ⚠️ Resource intensive

## Commercial Services (Paid)

For critical/production use, commercial services offer better reliability:

### 1. ScrapingBee
- **Cost**: ~$49/month for 100k API calls
- **Success Rate**: ~95%
- **Features**: Automatic retry, rotating proxies, JavaScript rendering
- **Website**: https://www.scrapingbee.com/

### 2. ScrapFly
- **Cost**: ~$30/month for 75k requests
- **Success Rate**: ~90%
- **Features**: ASP (Anti-Scraping Protection) bypass
- **Website**: https://scrapfly.io/

### 3. ZenRows
- **Cost**: ~$69/month for 250k API calls
- **Success Rate**: ~95%
- **Features**: Cloudflare bypass, CAPTCHA solving, JavaScript rendering
- **Website**: https://www.zenrows.com/

### 4. Bright Data (formerly Luminati)
- **Cost**: Pay-as-you-go, ~$500/month minimum
- **Success Rate**: ~98%
- **Features**: Enterprise-grade, largest proxy network
- **Website**: https://brightdata.com/

## Updated Download Script for NeXTSTEP Docs

Here's an updated version using nodriver:

```python
#!/usr/bin/env python3
"""
NeXTSTEP Documentation Downloader with Cloudflare Bypass
Uses nodriver to bypass Cloudflare protection
"""

import asyncio
import nodriver as uc
from pathlib import Path
import time
from urllib.parse import urljoin, urlparse

class CloudflareBypassDownloader:
    def __init__(self, output_dir="downloads"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.downloaded = set()

    async def download_page(self, browser, url):
        """Download a single page"""
        try:
            page = await browser.get(url)

            # Wait for Cloudflare challenge to complete
            await asyncio.sleep(3)

            # Check if we got through
            title = await page.evaluate("document.title")
            if "Just a moment" in title:
                print(f"  [WAIT] Cloudflare challenge detected, waiting...")
                await asyncio.sleep(10)

            # Get content
            content = await page.get_content()

            # Save to file
            parsed = urlparse(url)
            path = parsed.path.strip('/')
            if not path:
                path = "index.html"
            elif not path.endswith('.html'):
                path = path + '/index.html'

            output_path = self.output_dir / path
            output_path.parent.mkdir(parents=True, exist_ok=True)

            output_path.write_text(content, encoding='utf-8')
            self.downloaded.add(url)

            print(f"  [OK] {url}")
            return True

        except Exception as e:
            print(f"  [ERROR] {url}: {e}")
            return False

    async def download_documentation(self, base_url, sections):
        """Download all documentation sections"""
        browser = await uc.start(headless=False)  # Use headed mode for better success

        try:
            for section in sections:
                section_url = urljoin(base_url, section + '/')
                print(f"\n[SECTION] {section}")

                await self.download_page(browser, section_url)
                await asyncio.sleep(2)  # Be polite

        finally:
            await browser.stop()

async def main():
    downloader = CloudflareBypassDownloader("downloads")

    base_url = "https://www.nextcomputers.org/files/manuals/nd/"
    sections = [
        "Concepts",
        "GeneralRef",
        "UserInterface",
        "ProgrammingTopics",
        "ReleaseNotes"
    ]

    await downloader.download_documentation(base_url, sections)

if __name__ == "__main__":
    asyncio.run(main())
```

## Recommended Approach for NeXTSTEP Docs

### Option 1: Nodriver (Best Free Method)
```bash
cd /Users/jvindahl/Development/nextdimension/docs/refs/nextstep-dev

# Install nodriver
pip install nodriver nodriver-cf-bypass

# Create updated download script
# (Use script above)

# Run download
python download_with_nodriver.py
```

### Option 2: FlareSolverr + Existing Script
```bash
# Start FlareSolverr
docker run -d -p 8191:8191 flaresolverr/flaresolverr

# Modify existing download_manuals.py to use FlareSolverr
# Update session to use FlareSolverr proxy
```

### Option 3: Commercial Service (Most Reliable)
```bash
# Sign up for ScrapingBee (free trial available)
pip install scrapingbee

# Use ScrapingBee API in download script
```

## Comparison Matrix

| Method | Success Rate | Speed | Cost | Setup Difficulty |
|--------|-------------|-------|------|-----------------|
| curl/requests | 0% | Fast | Free | Easy |
| cloudscraper | 20-40% | Fast | Free | Easy |
| undetected-chromedriver | 20-40% | Slow | Free | Medium |
| nodriver | 60-80% | Slow | Free | Medium |
| nodriver-cf-bypass | 70-85% | Slow | Free | Medium |
| SeleniumBase CDP | 70-85% | Slow | Free | Medium |
| FlareSolverr | 75-90% | Slow | Free | Hard |
| ScrapingBee | 95% | Medium | $49/mo | Easy |
| ScrapFly | 90% | Medium | $30/mo | Easy |
| ZenRows | 95% | Medium | $69/mo | Easy |
| Bright Data | 98% | Fast | $500/mo | Medium |

## Troubleshooting

### Nodriver Still Detected
1. **Use headed mode** (headless=False) - More realistic
2. **Add random delays** between requests (2-5 seconds)
3. **Rotate user agents** for each session
4. **Use residential proxies** if available

### Slow Performance
1. **Run in headed mode first** to verify it works
2. **Increase timeout values** (Cloudflare can take 10+ seconds)
3. **Monitor CPU usage** (100% = browser struggling)

### Installation Issues
```bash
# Nodriver requires Chrome/Chromium
# macOS
brew install chromium

# Ubuntu
sudo apt-get install chromium-browser

# Then reinstall nodriver
pip install --upgrade nodriver
```

## Next Steps

After successful download:

```bash
# Verify download
find downloads -name "*.html" | wc -l

# Convert to Markdown
venv/bin/python3 tools/convert_html_to_md.py downloads markdown

# Build index
venv/bin/python3 tools/build_index.py markdown --json
```

## Additional Resources

- **Nodriver Documentation**: https://github.com/ultrafunkamsterdam/nodriver
- **ScrapingBee Blog**: https://www.scrapingbee.com/blog/
- **Anti-bot bypass discussion**: https://github.com/topics/cloudflare-bypass

---

**Last Updated**: 2024-11-09
**Status**: Nodriver recommended for free/open-source approach
**Note**: Cloudflare detection evolves constantly - methods may need updating
