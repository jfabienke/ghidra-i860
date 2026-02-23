# Quick Start Guide

Convert NeXTSTEP 3.3 Developer Documentation to Markdown in 3 easy steps.

## Prerequisites

### Python 3.8+

```bash
python3 --version  # Should be 3.8 or higher
```

### Install Dependencies

```bash
cd docs/refs/nextstep-dev
pip3 install -r requirements.txt
```

**Optional (for better PDF conversion):**

```bash
# macOS
brew install poppler

# Ubuntu/Debian
sudo apt-get install poppler-utils

# Then install Python package
pip3 install pdf2image pdfplumber
```

## Three-Step Conversion

### Step 1: Download Documentation

```bash
cd tools
python3 download_manuals.py --output-dir ../downloads
```

This downloads the HTML and PDF documentation from nextcomputers.org.

**Note:** If the download fails (403 errors), you can manually download from:
- https://www.nextcomputers.org/files/manuals/nd/

Place downloaded files in `downloads/` directory maintaining the structure.

### Step 2: Convert to Markdown

```bash
python3 convert_all.py --convert
```

This converts both HTML and PDF files to clean Markdown format.

### Step 3: Build Index

```bash
python3 build_index.py ../markdown
```

This creates a searchable index with cross-references.

## All-in-One Command

Or run everything at once:

```bash
python3 convert_all.py --all
```

## Output

Your converted documentation will be in:

```
docs/refs/nextstep-dev/
├── markdown/              # Converted Markdown files
│   ├── INDEX.md          # Master index
│   ├── Concepts/         # System concepts
│   ├── GeneralRef/       # API reference
│   ├── UserInterface/    # UI guidelines
│   └── ...
├── downloads/            # Downloaded originals
└── converted/            # Intermediate files
```

## Using the Documentation

### Human Reading

Open `markdown/INDEX.md` in your favorite Markdown viewer or text editor.

### With LLMs (Claude, GPT, etc.)

The converted Markdown is optimized for LLM consumption:

1. **Structured headers** - Easy to parse and navigate
2. **Code blocks** - Properly tagged with language identifiers
3. **Cross-references** - Preserved as relative links
4. **Metadata** - Each file has frontmatter with source info
5. **Clean formatting** - No HTML artifacts

### Search Tips

```bash
# Find all documents about PostScript
grep -r "PostScript" markdown/

# Find API references
grep -r "NS[A-Z][a-zA-Z]+" markdown/ | grep "class"

# Find code examples in Objective-C
grep -B5 -A10 "```objc" markdown/
```

## Troubleshooting

### Download Fails (403 Error)

The website may block automated downloads. Solutions:

1. **Manual Download:** Download sections manually from browser
2. **Rate Limiting:** Add `--delay 2.0` to slow down requests
3. **Alternative Source:** Try the alternate URL structure

### Poor PDF Conversion Quality

Install `pdfplumber` for better results:

```bash
pip3 install pdfplumber
python3 convert_pdf_to_md.py downloads/ converted/ --quality high
```

### Missing Dependencies

```bash
pip3 install beautifulsoup4 html2text PyPDF2 requests
```

### HTML Conversion Issues

The NeXTSTEP docs use `.htmld` directories. The converter handles this:

```
Input:  path/file.htmld/index.html
Output: path/file.md
```

## Advanced Usage

### Convert Specific Sections Only

```bash
python3 download_manuals.py --sections "Concepts,GeneralRef"
python3 convert_all.py --sections "Concepts,GeneralRef" --all
```

### Re-build Index After Manual Edits

```bash
python3 build_index.py ../markdown --json
```

### Custom Output Directory

```bash
python3 convert_all.py --base-dir /path/to/output --all
```

## Next Steps

1. Browse `markdown/INDEX.md` for organized navigation
2. Check section-specific directories for content
3. Use the JSON index (`INDEX.json`) for programmatic access
4. Reference converted docs in your NeXTdimension development

## Getting Help

- Check `README.md` for detailed documentation
- Review individual script help: `python3 script.py --help`
- Report issues specific to the conversion process
- For NeXTSTEP content questions, consult the original docs

## Contribution

Found conversion issues? Improvements needed?

1. Document the issue in `CONVERSION_NOTES.md`
2. Update the relevant conversion script
3. Re-run the conversion pipeline
4. Test the output quality

---

Happy documenting! 📚
