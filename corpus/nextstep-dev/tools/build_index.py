#!/usr/bin/env python3
"""
Documentation Index Builder for NeXTSTEP Documentation

Builds a comprehensive, searchable index of all converted Markdown documentation.
Creates cross-references, topic maps, and LLM-optimized navigation.

Usage:
    python3 build_index.py docs_dir [--output INDEX.md]
"""

import argparse
import os
import sys
import re
from pathlib import Path
from collections import defaultdict
import json
from datetime import datetime


class DocumentationIndexer:
    def __init__(self, docs_dir):
        self.docs_dir = Path(docs_dir)
        self.documents = []
        self.sections = defaultdict(list)
        self.topics = defaultdict(list)
        self.api_index = defaultdict(list)

    def extract_frontmatter(self, md_path):
        """Extract YAML frontmatter from Markdown file"""
        try:
            content = md_path.read_text(encoding='utf-8')

            if not content.startswith('---\n'):
                return None, content

            # Find closing ---
            end = content.find('\n---\n', 4)
            if end == -1:
                return None, content

            frontmatter_text = content[4:end]
            body = content[end + 5:]

            # Parse simple YAML
            frontmatter = {}
            for line in frontmatter_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    frontmatter[key] = value

            return frontmatter, body

        except Exception as e:
            print(f"  [WARN] Failed to parse {md_path.name}: {e}")
            return None, ""

    def extract_headers(self, content):
        """Extract all headers from Markdown content"""
        headers = []
        for line in content.split('\n'):
            match = re.match(r'^(#{1,6})\s+(.+)$', line)
            if match:
                level = len(match.group(1))
                text = match.group(2).strip()
                headers.append({'level': level, 'text': text})
        return headers

    def extract_code_blocks(self, content):
        """Extract code blocks and detect language"""
        code_blocks = []
        in_block = False
        current_block = []
        current_lang = ''

        for line in content.split('\n'):
            if line.startswith('```'):
                if in_block:
                    code_blocks.append({
                        'language': current_lang,
                        'code': '\n'.join(current_block)
                    })
                    current_block = []
                    current_lang = ''
                    in_block = False
                else:
                    current_lang = line[3:].strip()
                    in_block = True
            elif in_block:
                current_block.append(line)

        return code_blocks

    def detect_topics(self, frontmatter, content, headers):
        """Detect topics/keywords from document"""
        topics = set()

        # From frontmatter
        if frontmatter:
            if 'subject' in frontmatter:
                topics.add(frontmatter['subject'].lower())
            if 'section' in frontmatter:
                topics.add(frontmatter['section'].lower())

        # From headers
        for header in headers:
            if header['level'] <= 2:
                # Extract keywords from major headers
                words = re.findall(r'\b[A-Z][a-z]+\b', header['text'])
                topics.update(w.lower() for w in words if len(w) > 3)

        # Common API/technical terms
        technical_terms = [
            'object', 'class', 'method', 'function', 'api', 'protocol',
            'view', 'window', 'event', 'graphics', 'postscript', 'display',
            'i860', 'nextdimension', 'interface', 'application', 'framework',
            'database', 'indexing', 'sound', 'music', 'text', 'image'
        ]

        content_lower = content.lower()
        for term in technical_terms:
            if term in content_lower:
                topics.add(term)

        return list(topics)

    def detect_api_references(self, content):
        """Detect API references (class names, function names)"""
        apis = set()

        # Objective-C classes (start with capital letter, often have NS prefix)
        class_pattern = r'\b(NS[A-Z][a-zA-Z]+|[A-Z][a-z]+[A-Z][a-zA-Z]+)\b'
        apis.update(re.findall(class_pattern, content))

        # C functions (lowercase with underscores, followed by parentheses)
        func_pattern = r'\b([a-z_][a-z0-9_]+)\s*\('
        apis.update(re.findall(func_pattern, content))

        return list(apis)[:50]  # Limit to top 50

    def index_document(self, md_path):
        """Index a single Markdown document"""
        try:
            rel_path = md_path.relative_to(self.docs_dir)
            print(f"  [INDEX] {rel_path}")

            frontmatter, content = self.extract_frontmatter(md_path)

            if not frontmatter:
                frontmatter = {'title': md_path.stem}

            headers = self.extract_headers(content)
            code_blocks = self.extract_code_blocks(content)
            topics = self.detect_topics(frontmatter, content, headers)
            apis = self.detect_api_references(content)

            doc_info = {
                'path': str(rel_path),
                'title': frontmatter.get('title', md_path.stem),
                'section': frontmatter.get('section', rel_path.parts[0] if rel_path.parts else ''),
                'format': frontmatter.get('format', 'Unknown'),
                'headers': headers[:10],  # Top 10 headers
                'code_blocks': len(code_blocks),
                'topics': topics,
                'apis': apis,
                'size': len(content)
            }

            self.documents.append(doc_info)

            # Organize by section
            section = doc_info['section']
            self.sections[section].append(doc_info)

            # Organize by topics
            for topic in topics:
                self.topics[topic].append(doc_info)

            # Index APIs
            for api in apis:
                self.api_index[api].append(doc_info)

            return True

        except Exception as e:
            print(f"  [ERROR] Failed to index {md_path.name}: {e}")
            return False

    def index_all(self):
        """Index all Markdown files"""
        print("Building documentation index...")
        print()

        md_files = list(self.docs_dir.rglob('*.md'))
        md_files = [f for f in md_files if f.name not in ('README.md', 'INDEX.md')]

        if not md_files:
            print("No Markdown files found")
            return False

        print(f"Found {len(md_files)} documents\n")

        success = 0
        for md_file in md_files:
            if self.index_document(md_file):
                success += 1

        print(f"\n{'='*60}")
        print(f"Indexed {success} of {len(md_files)} documents")

        return True

    def generate_index_md(self, output_path):
        """Generate master INDEX.md file"""
        lines = [
            "# NeXTSTEP 3.3 Developer Documentation Index",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Documents:** {len(self.documents)}",
            f"**Sections:** {len(self.sections)}",
            "",
            "---",
            "",
        ]

        # Table of Contents
        lines.extend([
            "## Table of Contents",
            "",
            "- [Documentation by Section](#documentation-by-section)",
            "- [Documentation by Topic](#documentation-by-topic)",
            "- [API Reference Index](#api-reference-index)",
            "- [Quick Navigation](#quick-navigation)",
            "",
            "---",
            "",
        ])

        # Documentation by Section
        lines.extend([
            "## Documentation by Section",
            "",
        ])

        for section in sorted(self.sections.keys()):
            docs = self.sections[section]
            lines.append(f"### {section}")
            lines.append("")
            lines.append(f"*{len(docs)} documents*")
            lines.append("")

            for doc in sorted(docs, key=lambda d: d['title']):
                lines.append(f"- [{doc['title']}]({doc['path']})")
                if doc['headers']:
                    # Show top-level sections
                    for header in doc['headers'][:3]:
                        if header['level'] <= 2:
                            lines.append(f"  - {header['text']}")

            lines.append("")

        # Documentation by Topic
        lines.extend([
            "---",
            "",
            "## Documentation by Topic",
            "",
        ])

        # Show top 20 topics
        top_topics = sorted(self.topics.items(), key=lambda x: len(x[1]), reverse=True)[:20]

        for topic, docs in top_topics:
            lines.append(f"### {topic.title()}")
            lines.append("")
            for doc in docs[:5]:  # Top 5 docs per topic
                lines.append(f"- [{doc['title']}]({doc['path']})")
            if len(docs) > 5:
                lines.append(f"- *...and {len(docs) - 5} more*")
            lines.append("")

        # API Reference Index
        lines.extend([
            "---",
            "",
            "## API Reference Index",
            "",
        ])

        # Show top APIs
        top_apis = sorted(self.api_index.items(), key=lambda x: len(x[1]), reverse=True)[:50]

        lines.append("| API | Documents | Location |")
        lines.append("| --- | --------- | -------- |")

        for api, docs in top_apis:
            doc_count = len(docs)
            first_doc = docs[0]
            lines.append(f"| `{api}` | {doc_count} | [{first_doc['title']}]({first_doc['path']}) |")

        lines.append("")

        # Quick Navigation
        lines.extend([
            "---",
            "",
            "## Quick Navigation",
            "",
            "### Essential Documents",
            "",
        ])

        # Find key documents
        essential_keywords = ['introduction', 'overview', 'getting started', 'guide']
        essential_docs = []

        for doc in self.documents:
            title_lower = doc['title'].lower()
            if any(kw in title_lower for kw in essential_keywords):
                essential_docs.append(doc)

        for doc in essential_docs[:10]:
            lines.append(f"- [{doc['title']}]({doc['path']})")

        lines.extend([
            "",
            "### NeXTdimension-Specific",
            "",
        ])

        nd_keywords = ['nextdimension', 'i860', '3d', 'graphics', 'acceleration']
        nd_docs = []

        for doc in self.documents:
            content_lower = doc['title'].lower() + ' '.join(doc['topics'])
            if any(kw in content_lower for kw in nd_keywords):
                nd_docs.append(doc)

        for doc in nd_docs[:10]:
            lines.append(f"- [{doc['title']}]({doc['path']})")

        lines.extend([
            "",
            "---",
            "",
            "## Search Tips",
            "",
            "- Use your editor's search (Cmd/Ctrl+F) to find specific topics",
            "- Browse by section for organized navigation",
            "- Check the API index for specific classes/functions",
            "- Look for code examples using the topic index",
            "",
            "## For LLMs",
            "",
            "This index provides structured navigation of NeXTSTEP 3.3 documentation.",
            "All documents include frontmatter with metadata. Cross-references are",
            "preserved as relative links. Code examples are properly tagged with",
            "language identifiers.",
            "",
        ])

        # Write output
        output_path.write_text('\n'.join(lines), encoding='utf-8')
        print(f"\nIndex written to: {output_path}")

    def save_json_index(self, output_path):
        """Save machine-readable JSON index"""
        index_data = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_documents': len(self.documents),
                'sections': list(self.sections.keys()),
                'topics': list(self.topics.keys())
            },
            'documents': self.documents,
            'sections': dict(self.sections),
            'topics': {k: [d['path'] for d in v] for k, v in self.topics.items()},
            'api_index': {k: [d['path'] for d in v] for k, v in self.api_index.items()}
        }

        output_path.write_text(json.dumps(index_data, indent=2), encoding='utf-8')
        print(f"JSON index written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Build searchable index of documentation"
    )
    parser.add_argument(
        "docs_dir",
        help="Directory containing Markdown documentation"
    )
    parser.add_argument(
        "--output",
        help="Output file for Markdown index (default: INDEX.md)",
        default="INDEX.md"
    )
    parser.add_argument(
        "--json",
        help="Also output JSON index",
        action="store_true"
    )

    args = parser.parse_args()

    indexer = DocumentationIndexer(args.docs_dir)

    if not indexer.index_all():
        return 1

    # Generate Markdown index
    output_path = Path(args.docs_dir) / args.output
    indexer.generate_index_md(output_path)

    # Generate JSON index if requested
    if args.json:
        json_path = output_path.with_suffix('.json')
        indexer.save_json_index(json_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
