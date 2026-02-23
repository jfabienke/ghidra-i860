# Conversion Notes

This document tracks known issues, limitations, and best practices for converting NeXTSTEP documentation.

## Known Issues

### Download Limitations

1. **403 Errors**: nextcomputers.org may block automated downloads
   - **Solution**: Use `--delay 2.0` or manual download
   - **Alternative**: Try both base URLs in the script

2. **Directory Listings**: Some servers don't provide directory listings
   - **Impact**: May miss some files
   - **Solution**: Manually verify completeness against web browser

### HTML Conversion

1. **.htmld Directories**: NeXTSTEP uses `.htmld` as directory containers
   - **Handled**: Converter automatically processes these correctly
   - **Format**: `file.htmld/index.html` → `file.md`

2. **Nested Tables**: Complex nested tables may not convert perfectly
   - **Impact**: Minor formatting issues
   - **Solution**: Manual review of complex tables

3. **Image References**: Relative image paths need careful handling
   - **Status**: Basic support implemented
   - **TODO**: Enhance image extraction and path fixing

### PDF Conversion

1. **OCR Quality**: Scanned PDFs may have poor text extraction
   - **Solution**: Use `--quality high` with pdfplumber
   - **Alternative**: Manual transcription for critical sections

2. **Multi-column Layouts**: Complex layouts may lose structure
   - **Impact**: Text flow may be incorrect
   - **Solution**: Manual review and restructuring

3. **Code Blocks**: Code formatting may be lost in PDFs
   - **Partial Fix**: Structure detection attempts to recover
   - **TODO**: Improve code block detection heuristics

## Best Practices

### Before Conversion

1. **Check Downloads**: Verify files downloaded completely
2. **Install pdfplumber**: For high-quality PDF conversion
3. **Backup Originals**: Keep downloaded files safe

### During Conversion

1. **Monitor Output**: Watch for conversion errors
2. **Spot Check**: Review random samples for quality
3. **Log Issues**: Document problems in this file

### After Conversion

1. **Build Index**: Always run index builder
2. **Validate Links**: Check cross-references work
3. **Test Search**: Verify search functionality

## Section-Specific Notes

### Concepts

- Heavy use of diagrams (extract manually)
- Well-structured HTML
- Minimal conversion issues

### GeneralRef (API Reference)

- Contains many code examples
- Function signatures important to preserve
- Check code block formatting

### UserInterface

- Image-heavy documentation
- Screenshots need manual extraction
- Layout diagrams may need recreation

### ReleaseNotes

- Plain text format
- Usually converts well
- May contain version-specific info

## Improvement Opportunities

### Short-term

- [ ] Enhance code block detection
- [ ] Better table formatting
- [ ] Improve header level detection
- [ ] Fix image path resolution

### Medium-term

- [ ] Extract and optimize images
- [ ] Create diagram descriptions
- [ ] Add syntax highlighting hints
- [ ] Build API cross-reference map

### Long-term

- [ ] OCR for scanned PDFs
- [ ] Interactive examples
- [ ] Modern code examples (Swift/Rust)
- [ ] Video tutorials

## Testing Checklist

When adding improvements, test:

- [ ] Simple HTML pages convert correctly
- [ ] .htmld directories process properly
- [ ] PDF text extraction is accurate
- [ ] Code blocks preserve formatting
- [ ] Links are updated correctly
- [ ] Images are extracted (if enabled)
- [ ] Index builds successfully
- [ ] JSON index is valid
- [ ] Cross-references work

## Conversion Statistics

Track conversion quality here:

### Initial Conversion (Date: ______)

- Total files processed: ___
- Successful conversions: ___
- Failed conversions: ___
- Manual intervention needed: ___

### Quality Metrics

- Code blocks correctly formatted: ___%
- Links working: ___%
- Tables readable: ___%
- Overall quality: ___/10

## Common Patterns

### Code Block Patterns

```
// Objective-C
@interface ClassName : SuperClass

// C
void function_name(int param);

// PostScript
/Times-Roman findfont 12 scalefont setfont
```

### Header Patterns

```
All caps = H2
Title Case = H3
Numbered (1.1) = H3 or H4
```

### Link Patterns

```
Internal: ../Section/File.md
External: https://...
API: #anchor
```

## Tool-Specific Notes

### download_manuals.py

- Uses requests with User-Agent
- Respects --delay between requests
- Saves manifest for tracking

### convert_html_to_md.py

- Uses BeautifulSoup for parsing
- html2text for conversion (if available)
- Handles .htmld directories specially

### convert_pdf_to_md.py

- PyPDF2 as fallback
- pdfplumber for quality (recommended)
- Structure detection for formatting

### build_index.py

- Parses YAML frontmatter
- Extracts headers and topics
- Builds multiple indexes (section, topic, API)

## Contributing

When you encounter conversion issues:

1. Document the issue here
2. Include example files (if possible)
3. Propose solution approach
4. Update relevant script
5. Test thoroughly
6. Update this document

---

Last updated: 2025-11-09
