# Manual Download Guide

The nextcomputers.org website blocks automated downloads (HTTP 403 errors). You'll need to download the documentation manually using your web browser.

## Why Manual Download is Needed

The server returns `403 Forbidden` for automated requests, even with proper User-Agent headers. This is a common anti-bot protection.

## Method 1: Browser Extension (Recommended)

Use a browser extension like **DownThemAll** or **HTTrack** to recursively download:

### Using HTTrack (Free, Cross-platform)

1. **Install HTTrack**
   ```bash
   # macOS
   brew install httrack

   # Ubuntu/Debian
   sudo apt-get install httrack
   ```

2. **Download the documentation**
   ```bash
   cd /Users/jvindahl/Development/nextdimension/docs/refs/nextstep-dev

   httrack https://www.nextcomputers.org/files/manuals/nd/ \
     -O downloads \
     --max-depth=10 \
     --ext-depth=10 \
     --near \
     --robots=0 \
     --keep-alive \
     --connection-per-second=1
   ```

3. **Wait for completion** (may take 30-60 minutes)

## Method 2: wget with Delays

```bash
cd /Users/jvindahl/Development/nextdimension/docs/refs/nextstep-dev

wget \
  --recursive \
  --level=10 \
  --no-parent \
  --page-requisites \
  --adjust-extension \
  --convert-links \
  --wait=2 \
  --random-wait \
  --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  --directory-prefix=downloads \
  https://www.nextcomputers.org/files/manuals/nd/
```

## Method 3: Manual Browser Download

If automated methods fail:

1. **Open in Browser**: https://www.nextcomputers.org/files/manuals/nd/

2. **Navigate and Save**:
   - Browse to each section (Concepts, GeneralRef, etc.)
   - Right-click → "Save Page As..."
   - Choose "Webpage, Complete" format
   - Save to `downloads/[SectionName]/`

3. **Important Directories**:
   ```
   downloads/
   ├── Concepts/
   ├── GeneralRef/
   ├── UserInterface/
   ├── ProgrammingTopics/
   ├── ReleaseNotes/
   └── Pre3.0_Concepts/
   ```

## Key URLs to Download

Based on the search results, these URLs are confirmed to exist:

### Concepts
- https://www.nextcomputers.org/NeXTfiles/Docs/NeXTStep/3.3/nd/Concepts/Pre3.0_Concepts/01_SysOver.htmld/index.html

### GeneralRef
- https://nextcomputers.org/files/manuals/nd/GeneralRef/00_Introduction/Intro.htmld/index.html

### UserInterface
- https://www.nextcomputers.org/files/manuals/nd/UserInterface/04_Window/Window.htmld/index.html

### ReleaseNotes
- https://www.nextcomputers.org/files/manuals/nd/ReleaseNotes/InterfaceBuilder.htmld/index.html
- https://www.nextcomputers.org/files/manuals/nd/ReleaseNotes/Compiler.htmld/index.html
- https://www.nextcomputers.org/files/manuals/nd/ReleaseNotes/libg++.htmld/index.html

## After Download

Once you have downloaded the files:

```bash
cd /Users/jvindahl/Development/nextdimension/docs/refs/nextstep-dev

# Verify download
ls -R downloads/

# Convert to Markdown
venv/bin/python3 tools/convert_all.py --convert

# Build index
venv/bin/python3 tools/build_index.py markdown --json
```

## Alternative: Archive.org

The Internet Archive may have archived versions:

1. Visit: https://web.archive.org/
2. Search for: `https://www.nextcomputers.org/files/manuals/nd/`
3. Select a snapshot date
4. Download using browser or wget

## Troubleshooting

### 403 Errors Even with Manual Tools

- **Try different User-Agent**: Some servers check
- **Add delays**: Use `--wait=2 --random-wait`
- **Use VPN**: IP-based rate limiting
- **Contact site admin**: Request bulk download permission

### Incomplete Downloads

- Check `downloads/download_manifest.json` after wget/httrack
- Compare with online directory listings
- Re-run for specific missing sections

## Next Steps

After successful download:

1. **Verify Structure**:
   ```bash
   find downloads -name "*.html" | wc -l
   find downloads -name "*.pdf" | wc -l
   ```

2. **Convert**:
   ```bash
   venv/bin/python3 tools/convert_all.py --convert
   ```

3. **Review Quality**:
   ```bash
   ls -lh markdown/
   ```

## Contact

If you successfully download the documentation, consider:
- Sharing with the NeXTdimension project
- Creating a mirror for preservation
- Uploading to Archive.org if not already present

---

**Note**: Respect the website's robots.txt and terms of service. Add appropriate delays between requests.
