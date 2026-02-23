# NeXTSTEP 3.3 Developer Documentation

This directory contains converted Markdown versions of the NeXTSTEP 3.3 Developer Documentation manuals.

## Source

Original documentation: https://www.nextcomputers.org/files/manuals/nd/

The NeXTSTEP 3.3 Developer's Library contains comprehensive documentation for developing applications on the NeXTSTEP platform.

## Documentation Structure

The NeXTSTEP 3.3 Developer Documentation is organized into several major sections:

### Core Documentation

1. **Concepts** - System architecture and programming concepts
   - System Overview
   - Object-Oriented Programming
   - Application Architecture
   - Dynamic Loading
   - Distributed Objects
   - PostScript and Display PostScript

2. **General Reference** - API reference and specifications
   - Introduction
   - Foundation Framework
   - Application Kit
   - Database Kit
   - Indexing Kit
   - 3D Graphics Library

3. **User Interface Guidelines** - UI design and HIG
   - Interface Design
   - Windows and Panels
   - Menus
   - Controls and Views
   - Common User Interface Elements

4. **Programming Topics** - Specific implementation guides
   - Application Programming
   - Event Handling
   - Drawing and Imaging
   - Sound and Music
   - Text Processing
   - Database Access

5. **Release Notes** - Version-specific information
   - Interface Builder
   - Compiler
   - Libraries (libg++, etc.)
   - System Updates

### NeXTdimension-Specific Documentation

Since this is the NeXTdimension project, pay special attention to:
- **3D Graphics** - i860 acceleration capabilities
- **Display PostScript** - Rendering acceleration
- **Performance optimization** - Hardware acceleration topics
- **Device drivers** - Hardware interface documentation

## Conversion Tools

This directory includes scripts for converting the original documentation:

- `download_manuals.py` - Downloads manuals from nextcomputers.org
- `convert_pdf_to_md.py` - Converts PDF manuals to Markdown
- `convert_html_to_md.py` - Converts HTML documentation to Markdown
- `build_index.py` - Generates searchable index and cross-references

## Usage

### Step 1: Download Documentation

```bash
# Download all manuals (requires internet connection)
python3 download_manuals.py

# Download specific sections only
python3 download_manuals.py --sections Concepts,GeneralRef
```

### Step 2: Convert to Markdown

```bash
# Convert all downloaded files
python3 convert_all.py

# Convert specific format
python3 convert_pdf_to_md.py input_dir output_dir
python3 convert_html_to_md.py input_dir output_dir
```

### Step 3: Build Index

```bash
# Generate master index and cross-references
python3 build_index.py
```

## Output Structure

```
nextstep-dev/
├── README.md                    # This file
├── INDEX.md                     # Master index (generated)
├── tools/                       # Conversion scripts
│   ├── download_manuals.py
│   ├── convert_pdf_to_md.py
│   ├── convert_html_to_md.py
│   └── build_index.py
├── Concepts/                    # System concepts
├── GeneralRef/                  # API reference
├── UserInterface/               # UI guidelines
├── ProgrammingTopics/           # Implementation guides
├── ReleaseNotes/                # Version info
└── NeXTdimension/               # ND-specific docs
```

## Dependencies

### Python Packages

```bash
pip install beautifulsoup4 html2text pypdf2 markdown requests
```

### Optional (for better PDF conversion)

```bash
# macOS
brew install poppler

# Linux
apt-get install poppler-utils

# Then install:
pip install pdf2image pdfplumber
```

## Markdown Format

The converted documentation follows these conventions:

- **Headers**: Use ATX-style headers (`#`, `##`, `###`)
- **Code blocks**: Fenced with triple backticks, language-tagged
- **Links**: Preserve internal cross-references
- **Images**: Extracted and stored in `images/` subdirectories
- **Tables**: Converted to GitHub Flavored Markdown tables
- **Metadata**: Each file includes frontmatter with source info

### Example Frontmatter

```yaml
---
title: "System Overview"
source: "https://www.nextcomputers.org/files/manuals/nd/Concepts/01_SysOver.htmld/"
section: "Concepts"
converted: "2025-11-09"
format: "HTML"
---
```

## LLM Optimization

The converted Markdown is optimized for Large Language Model consumption:

1. **Clean structure**: Consistent heading hierarchy
2. **Code examples**: Properly tagged with language identifiers
3. **Cross-references**: Maintained as relative links
4. **Searchable index**: Full-text index with topic mapping
5. **Context preservation**: Original structure and relationships maintained

## Contributing

When adding new conversions:

1. Maintain consistent Markdown formatting
2. Preserve original technical accuracy
3. Update the master index
4. Document any conversion issues in `CONVERSION_NOTES.md`

## License

The original NeXTSTEP documentation is copyright NeXT Computer, Inc. This conversion is for preservation and educational purposes.

## Related Documentation

- [i860 Processor Documentation](../../../i860/)
- [NeXTdimension Hardware Specifications](../../hardware/)
- [Display PostScript Reference](../../postscript/)
