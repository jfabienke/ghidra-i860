#!/usr/bin/env python3
"""
Setup Verification Script

Verifies that all dependencies are installed and tools are ready to use.

Usage:
    python3 verify_setup.py
"""

import sys
from pathlib import Path


def check_python_version():
    """Check Python version"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} (need 3.8+)")
        return False


def check_dependencies():
    """Check required Python packages"""
    print("\nChecking required dependencies...")

    required = {
        'bs4': 'beautifulsoup4',
        'html2text': 'html2text',
        'PyPDF2': 'PyPDF2',
        'requests': 'requests',
    }

    optional = {
        'pdfplumber': 'pdfplumber (recommended for better PDF quality)',
        'pdf2image': 'pdf2image (for image extraction)',
    }

    all_ok = True

    for module, package in required.items():
        try:
            __import__(module)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} - Install with: pip install {package}")
            all_ok = False

    print("\nChecking optional dependencies...")
    for module, package in optional.items():
        try:
            __import__(module)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ○ {package} - Install for better quality")

    return all_ok


def check_tools():
    """Check that all tool scripts exist"""
    print("\nChecking conversion tools...")

    tools_dir = Path(__file__).parent
    required_tools = [
        'download_manuals.py',
        'convert_pdf_to_md.py',
        'convert_html_to_md.py',
        'build_index.py',
        'convert_all.py',
    ]

    all_ok = True
    for tool in required_tools:
        tool_path = tools_dir / tool
        if tool_path.exists():
            print(f"  ✓ {tool}")
        else:
            print(f"  ✗ {tool} - Missing!")
            all_ok = False

    return all_ok


def check_directories():
    """Check directory structure"""
    print("\nChecking directory structure...")

    base_dir = Path(__file__).parent.parent
    required_dirs = [
        ('tools', 'Tools directory'),
    ]

    for dir_name, description in required_dirs:
        dir_path = base_dir / dir_name
        if dir_path.exists() and dir_path.is_dir():
            print(f"  ✓ {description}")
        else:
            print(f"  ✗ {description} - Missing!")

    # Check if output directories can be created
    test_dirs = ['downloads', 'converted', 'markdown']
    print("\nChecking write permissions...")
    for dir_name in test_dirs:
        test_path = base_dir / dir_name
        try:
            test_path.mkdir(exist_ok=True)
            print(f"  ✓ Can create {dir_name}/ directory")
        except Exception as e:
            print(f"  ✗ Cannot create {dir_name}/ directory: {e}")

    return True


def check_documentation():
    """Check that documentation files exist"""
    print("\nChecking documentation...")

    base_dir = Path(__file__).parent.parent
    docs = [
        'README.md',
        'QUICKSTART.md',
        'SUMMARY.md',
        'CONVERSION_NOTES.md',
        'requirements.txt',
    ]

    all_ok = True
    for doc in docs:
        doc_path = base_dir / doc
        if doc_path.exists():
            print(f"  ✓ {doc}")
        else:
            print(f"  ✗ {doc} - Missing!")
            all_ok = False

    return all_ok


def run_quick_test():
    """Run a quick functionality test"""
    print("\nRunning quick functionality test...")

    try:
        from bs4 import BeautifulSoup
        html = "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>"
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.find('title').string
        if title == "Test":
            print("  ✓ HTML parsing works")
        else:
            print("  ✗ HTML parsing failed")
            return False

        import PyPDF2
        print("  ✓ PDF library loads")

        import requests
        print("  ✓ HTTP library loads")

        return True

    except Exception as e:
        print(f"  ✗ Functionality test failed: {e}")
        return False


def print_next_steps(all_ok):
    """Print next steps"""
    print("\n" + "="*60)

    if all_ok:
        print("✓ Setup verification complete - All checks passed!")
        print("="*60)
        print("\nYou're ready to convert NeXTSTEP documentation!")
        print("\nNext steps:")
        print("  1. Review QUICKSTART.md for usage instructions")
        print("  2. Run: python3 convert_all.py --all")
        print("  3. Browse the results in markdown/INDEX.md")
    else:
        print("✗ Setup verification found issues")
        print("="*60)
        print("\nPlease fix the issues above before proceeding.")
        print("\nCommon fixes:")
        print("  - Install dependencies: pip3 install -r requirements.txt")
        print("  - Check file permissions in this directory")
        print("  - Verify all tool scripts are present")


def main():
    print("="*60)
    print("NeXTSTEP Documentation Conversion - Setup Verification")
    print("="*60)
    print()

    checks = [
        check_python_version(),
        check_dependencies(),
        check_tools(),
        check_directories(),
        check_documentation(),
        run_quick_test(),
    ]

    all_ok = all(checks)
    print_next_steps(all_ok)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
