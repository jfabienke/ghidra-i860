#!/usr/bin/env python3
"""
Master Conversion Script for NeXTSTEP Documentation

Orchestrates the complete conversion pipeline:
1. Download documentation
2. Convert PDFs to Markdown
3. Convert HTML to Markdown
4. Build searchable index

Usage:
    python3 convert_all.py [--download] [--convert] [--index] [--all]
"""

import argparse
import sys
import subprocess
from pathlib import Path


class ConversionPipeline:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.tools_dir = self.base_dir / "tools"
        self.downloads_dir = self.base_dir / "downloads"
        self.output_dir = self.base_dir / "converted"

    def run_script(self, script_name, args):
        """Run a Python script with arguments"""
        script_path = self.tools_dir / script_name
        cmd = [sys.executable, str(script_path)] + args

        print(f"\n{'='*60}")
        print(f"Running: {script_name}")
        print(f"{'='*60}\n")

        try:
            result = subprocess.run(cmd, check=True)
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            print(f"\nError running {script_name}: {e}")
            return False

    def step_download(self, sections=None):
        """Step 1: Download documentation"""
        args = [
            "--output-dir", str(self.downloads_dir),
            "--delay", "1.0"
        ]

        if sections:
            args.extend(["--sections", sections])

        return self.run_script("download_manuals.py", args)

    def step_convert_pdf(self):
        """Step 2: Convert PDFs to Markdown"""
        pdf_output = self.output_dir / "from_pdf"
        args = [
            str(self.downloads_dir),
            str(pdf_output),
            "--quality", "high"
        ]

        return self.run_script("convert_pdf_to_md.py", args)

    def step_convert_html(self):
        """Step 3: Convert HTML to Markdown"""
        html_output = self.output_dir / "from_html"
        args = [
            str(self.downloads_dir),
            str(html_output),
            "--preserve-structure",
            "--extract-images"
        ]

        return self.run_script("convert_html_to_md.py", args)

    def step_merge_outputs(self):
        """Step 4: Merge PDF and HTML conversions"""
        print(f"\n{'='*60}")
        print(f"Merging converted documents")
        print(f"{'='*60}\n")

        merged_dir = self.base_dir / "markdown"
        merged_dir.mkdir(exist_ok=True)

        # Copy HTML conversions (primary source)
        html_dir = self.output_dir / "from_html"
        if html_dir.exists():
            import shutil
            for item in html_dir.rglob('*'):
                if item.is_file():
                    rel_path = item.relative_to(html_dir)
                    dest = merged_dir / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest)
                    print(f"  [COPY] {rel_path}")

        # Add PDF conversions (fill gaps)
        pdf_dir = self.output_dir / "from_pdf"
        if pdf_dir.exists():
            for item in pdf_dir.rglob('*'):
                if item.is_file():
                    rel_path = item.relative_to(pdf_dir)
                    dest = merged_dir / rel_path
                    if not dest.exists():
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item, dest)
                        print(f"  [ADD] {rel_path}")

        print(f"\nMerged documentation to: {merged_dir}")
        return True

    def step_build_index(self):
        """Step 5: Build searchable index"""
        merged_dir = self.base_dir / "markdown"
        args = [
            str(merged_dir),
            "--output", "INDEX.md",
            "--json"
        ]

        return self.run_script("build_index.py", args)

    def run_all(self, download=True, sections=None):
        """Run complete conversion pipeline"""
        print("="*60)
        print("NeXTSTEP Documentation Conversion Pipeline")
        print("="*60)

        steps = [
            ("Download", lambda: self.step_download(sections) if download else True),
            ("Convert PDFs", self.step_convert_pdf),
            ("Convert HTML", self.step_convert_html),
            ("Merge outputs", self.step_merge_outputs),
            ("Build index", self.step_build_index),
        ]

        for step_name, step_func in steps:
            print(f"\n{'#'*60}")
            print(f"# Step: {step_name}")
            print(f"{'#'*60}\n")

            if not step_func():
                print(f"\nError: {step_name} failed")
                return False

        print("\n" + "="*60)
        print("Conversion Complete!")
        print("="*60)
        print(f"\nDocumentation available at: {self.base_dir / 'markdown'}")
        print(f"Index available at: {self.base_dir / 'markdown' / 'INDEX.md'}")

        return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert all NeXTSTEP documentation to Markdown"
    )
    parser.add_argument(
        "--base-dir",
        help="Base directory for conversion (default: current directory)",
        default="."
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download documentation (skip if already downloaded)"
    )
    parser.add_argument(
        "--sections",
        help="Comma-separated list of sections to process",
        default=None
    )
    parser.add_argument(
        "--convert",
        action="store_true",
        help="Only run conversion (skip download)"
    )
    parser.add_argument(
        "--index",
        action="store_true",
        help="Only build index (skip download and conversion)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run complete pipeline (download + convert + index)"
    )

    args = parser.parse_args()

    pipeline = ConversionPipeline(args.base_dir)

    # Determine what to run
    if args.all:
        success = pipeline.run_all(download=True, sections=args.sections)
    elif args.index:
        success = pipeline.step_build_index()
    elif args.convert:
        success = (
            pipeline.step_convert_pdf() and
            pipeline.step_convert_html() and
            pipeline.step_merge_outputs() and
            pipeline.step_build_index()
        )
    elif args.download:
        success = pipeline.step_download(args.sections)
    else:
        # Default: convert and index (assume already downloaded)
        success = (
            pipeline.step_convert_pdf() and
            pipeline.step_convert_html() and
            pipeline.step_merge_outputs() and
            pipeline.step_build_index()
        )

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
