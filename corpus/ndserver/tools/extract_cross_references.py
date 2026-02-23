#!/usr/bin/env python3
"""
Extract cross-references from analyzed NDserver function documentation.

This script parses all function .md files to extract:
- Global variables and their accesses
- Data structures and field mappings
- Hardware registers
- Library function calls
- String constants
- Call graph relationships
"""

import json
import re
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

class CrossReferenceExtractor:
    def __init__(self, docs_dir, database_dir):
        self.docs_dir = Path(docs_dir)
        self.database_dir = Path(database_dir)

        # Storage for extracted data
        self.global_vars = defaultdict(lambda: {
            "addresses": set(),
            "accessed_by": [],
            "type": None,
            "size": None,
            "purpose": None,
            "evidence": []
        })

        self.hardware_regs = defaultdict(lambda: {
            "accessed_by": [],
            "name": None,
            "size": None,
            "purpose": None,
            "bit_fields": []
        })

        self.data_structures = defaultdict(lambda: {
            "size": None,
            "fields": [],
            "references": [],
            "completeness": 0
        })

        self.library_calls = defaultdict(lambda: {
            "callers": [],
            "total_calls": 0,
            "error_handling": 0
        })

        self.string_constants = {}
        self.call_chains = []

        # Statistics
        self.analyzed_functions = []
        self.total_functions = 0

    def extract_from_markdown(self, md_file):
        """Extract cross-references from a single function markdown file."""
        with open(md_file, 'r') as f:
            content = f.read()

        # Extract function address and name from filename
        filename = md_file.name
        match = re.match(r'([0-9a-fA-F]{8})_(.+)\.md', filename)
        if not match:
            print(f"  WARNING: Skipping {filename} - doesn't match expected pattern")
            return None

        func_addr = "0x" + match.group(1).lower()
        func_name = match.group(2)

        func_info = {
            "address": func_addr,
            "name": func_name,
            "file": str(md_file)
        }

        self.analyzed_functions.append(func_info)

        # Extract global variable accesses
        self._extract_global_vars(content, func_info)

        # Extract hardware register accesses
        self._extract_hardware_regs(content, func_info)

        # Extract data structure information
        self._extract_data_structures(content, func_info)

        # Extract library calls
        self._extract_library_calls(content, func_info)

        # Extract string constants
        self._extract_strings(content, func_info)

        return func_info

    def _extract_global_vars(self, content, func_info):
        """Extract global variable accesses from markdown content."""
        # Pattern: 0xXXXXXXXX in various contexts
        # Look for addresses in specific sections

        # Find "Global Data" or "Memory Regions Accessed" sections
        global_section = re.search(r'###?\s+Global\s+(?:Data|Variables).*?(?=###|\Z)', content, re.DOTALL | re.IGNORECASE)
        if global_section:
            section_text = global_section.group(0)

            # Extract addresses and descriptions
            # Pattern: 0xXXXXXXXX: Description
            for match in re.finditer(r'(0x[0-9A-Fa-f]{8})\s*:\s*([^\n]+)', section_text):
                addr = match.group(1).lower()
                desc = match.group(2).strip()

                self.global_vars[addr]["addresses"].add(addr)
                self.global_vars[addr]["accessed_by"].append({
                    "function": func_info["address"],
                    "name": func_info["name"],
                    "context": desc
                })

                # Try to infer type and purpose
                if not self.global_vars[addr]["purpose"]:
                    self.global_vars[addr]["purpose"] = desc

                # Look for size information
                size_match = re.search(r'\((\d+)\s*bytes?\)', desc)
                if size_match and not self.global_vars[addr]["size"]:
                    self.global_vars[addr]["size"] = int(size_match.group(1))

        # Also extract from disassembly comments
        disasm_section = re.search(r'```asm.*?```', content, re.DOTALL)
        if disasm_section:
            asm_text = disasm_section.group(0)

            # Look for absolute address accesses
            for match in re.finditer(r'move\.\w+\s+\((0x[0-9A-Fa-f]{8})\)\.l', asm_text, re.IGNORECASE):
                addr = match.group(1).lower()

                # Add to global vars if not already tracked from this function
                already_tracked = any(
                    info.get("function") == func_info["address"]
                    for info in self.global_vars[addr]["accessed_by"]
                )
                if not already_tracked:
                    self.global_vars[addr]["accessed_by"].append({
                        "function": func_info["address"],
                        "name": func_info["name"],
                        "access": "read/write"
                    })

    def _extract_hardware_regs(self, content, func_info):
        """Extract hardware register accesses."""
        # Look for "Hardware Access" or "Hardware Registers" sections
        hw_section = re.search(r'###?\s+Hardware\s+(?:Access|Registers).*?(?=###|\Z)', content, re.DOTALL | re.IGNORECASE)
        if hw_section:
            section_text = hw_section.group(0)

            # Extract register addresses
            for match in re.finditer(r'(0x[0-9A-Fa-f]{8})\s*:\s*([^\n]+)', section_text):
                addr = match.group(1).lower()
                desc = match.group(2).strip()

                self.hardware_regs[addr]["accessed_by"].append({
                    "function": func_info["address"],
                    "name": func_info["name"],
                    "context": desc
                })

                if not self.hardware_regs[addr]["purpose"]:
                    self.hardware_regs[addr]["purpose"] = desc

    def _extract_data_structures(self, content, func_info):
        """Extract data structure field mappings."""
        # Look for structure allocation
        alloc_pattern = r'malloc\s*\(\s*(\d+)\s*\)'
        for match in re.finditer(alloc_pattern, content):
            size = int(match.group(1))

            # Try to determine structure name from context
            context = content[max(0, match.start()-200):match.start()]
            struct_match = re.search(r'(\w+(?:_t)?)\s*(?:structure|struct)', context, re.IGNORECASE)

            if struct_match:
                struct_name = struct_match.group(1)
            else:
                struct_name = f"struct_{size}bytes"

            if not self.data_structures[struct_name]["size"]:
                self.data_structures[struct_name]["size"] = size

            self.data_structures[struct_name]["references"].append({
                "function": func_info["address"],
                "allocation": True,
                "source": f"malloc({size})"
            })

        # Extract field accesses (e.g., "0x4,A2" or "+0x08")
        field_pattern = r'\((?:0x)?([0-9a-f]+),\s*A[0-9]\)'
        for match in re.finditer(field_pattern, content):
            offset = int(match.group(1), 16)
            # Store field access (would need more context to map to specific struct)

    def _extract_library_calls(self, content, func_info):
        """Extract library function calls."""
        # Look for "Library Calls" or "OS Functions" sections
        lib_section = re.search(r'###?\s+(?:Library|OS\s+Functions).*?(?=###|\Z)', content, re.DOTALL | re.IGNORECASE)
        if lib_section:
            section_text = lib_section.group(0)

            # Extract function names
            for match in re.finditer(r'\*\*(?:\d+\.\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\*\*', section_text):
                lib_func = match.group(1)

                self.library_calls[lib_func]["callers"].append({
                    "function": func_info["address"],
                    "name": func_info["name"]
                })
                self.library_calls[lib_func]["total_calls"] += 1

                # Check for error handling
                context = section_text[match.start():min(len(section_text), match.end()+500)]
                if re.search(r'error|check|validate|NULL', context, re.IGNORECASE):
                    self.library_calls[lib_func]["error_handling"] += 1

    def _extract_strings(self, content, func_info):
        """Extract string constants."""
        # Look for string literals in various formats
        for match in re.finditer(r'["\']([^"\']{10,})["\']', content):
            string_val = match.group(1)

            # Look for associated address
            context = content[max(0, match.start()-100):match.start()]
            addr_match = re.search(r'0x([0-9A-Fa-f]{8})', context)

            if addr_match:
                addr = "0x" + addr_match.group(1).lower()
                self.string_constants[string_val] = {
                    "address": addr,
                    "used_by": [func_info["address"]],
                    "context": "unknown"
                }

    def process_all_functions(self):
        """Process all function markdown files."""
        functions_dir = self.docs_dir / "functions"

        if not functions_dir.exists():
            print(f"Error: Functions directory not found: {functions_dir}")
            return

        # Get all analyzed function files (excluding 0x prefix which are stubs)
        all_md_files = sorted(functions_dir.glob('*.md'))
        md_files = [f for f in all_md_files if not f.name.startswith('0x')]

        print(f"Found {len(md_files)} analyzed function documentation files")

        for md_file in md_files:
            print(f"  Processing: {md_file.name}")
            self.extract_from_markdown(md_file)

    def generate_json_database(self):
        """Generate JSON cross-reference database."""
        # Convert sets to lists for JSON serialization
        global_vars_serializable = {}
        for addr, data in self.global_vars.items():
            global_vars_serializable[addr] = {
                "name": f"g_var_{addr.replace('0x', '')}",  # Placeholder name
                "type": data["type"],
                "size": data["size"],
                "purpose": data["purpose"],
                "accessed_by": data["accessed_by"],
                "evidence": data["evidence"]
            }

        database = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "analyzed_functions": len(self.analyzed_functions),
                "total_functions": self.total_functions,
                "confidence": "high for analyzed, medium for inferred"
            },
            "global_variables": global_vars_serializable,
            "hardware_registers": dict(self.hardware_regs),
            "data_structures": dict(self.data_structures),
            "library_functions": dict(self.library_calls),
            "string_constants": self.string_constants,
            "call_chains": self.call_chains,
            "analyzed_functions": self.analyzed_functions
        }

        output_file = self.database_dir / "cross_references.json"
        with open(output_file, 'w') as f:
            json.dump(database, f, indent=2)

        print(f"\nGenerated: {output_file}")
        print(f"  Size: {output_file.stat().st_size:,} bytes")

        return database

    def generate_statistics(self, database):
        """Generate statistics report."""
        stats = {
            "total_global_vars": len(database["global_variables"]),
            "total_hardware_regs": len(database["hardware_registers"]),
            "total_data_structures": len(database["data_structures"]),
            "total_library_functions": len(database["library_functions"]),
            "total_strings": len(database["string_constants"]),
            "analyzed_functions": len(self.analyzed_functions)
        }

        # Find "hottest" globals
        hottest = sorted(
            [(addr, len(data["accessed_by"])) for addr, data in database["global_variables"].items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]

        stats["hottest_globals"] = [
            {"address": addr, "access_count": count} for addr, count in hottest
        ]

        # Most complete data structure
        if database["data_structures"]:
            most_complete = max(
                database["data_structures"].items(),
                key=lambda x: x[1].get("completeness", 0)
            )
            stats["most_complete_struct"] = {
                "name": most_complete[0],
                "completeness": most_complete[1].get("completeness", 0)
            }

        return stats

def main():
    # Paths
    repo_root = Path(__file__).parent.parent
    docs_dir = repo_root / "docs"
    database_dir = repo_root / "database"

    print("NDserver Cross-Reference Extractor")
    print("=" * 60)

    extractor = CrossReferenceExtractor(docs_dir, database_dir)

    # Process all function documentation
    extractor.process_all_functions()

    # Load existing analysis order to get total function count
    analysis_order_file = database_dir / "analysis_order.json"
    if analysis_order_file.exists():
        with open(analysis_order_file) as f:
            analysis_order = json.load(f)
            if isinstance(analysis_order, list):
                extractor.total_functions = len(analysis_order)
            elif isinstance(analysis_order, dict):
                extractor.total_functions = len(analysis_order.get("layers", {}).get("0", [])) + \
                                           len(analysis_order.get("layers", {}).get("1", [])) + \
                                           len(analysis_order.get("layers", {}).get("2", [])) + \
                                           len(analysis_order.get("layers", {}).get("3", [])) + \
                                           len(analysis_order.get("isolated", []))

    # Generate JSON database
    database = extractor.generate_json_database()

    # Generate statistics
    stats = extractor.generate_statistics(database)

    print("\n" + "=" * 60)
    print("EXTRACTION STATISTICS")
    print("=" * 60)
    print(f"Analyzed Functions: {stats['analyzed_functions']}")
    print(f"Global Variables: {stats['total_global_vars']}")
    print(f"Hardware Registers: {stats['total_hardware_regs']}")
    print(f"Data Structures: {stats['total_data_structures']}")
    print(f"Library Functions: {stats['total_library_functions']}")
    print(f"String Constants: {stats['total_strings']}")

    if stats.get("hottest_globals"):
        print("\nTop 5 Hottest Globals:")
        for item in stats["hottest_globals"]:
            print(f"  {item['address']}: {item['access_count']} accesses")

    if stats.get("most_complete_struct"):
        print(f"\nMost Complete Struct: {stats['most_complete_struct']['name']}")
        print(f"  Completeness: {stats['most_complete_struct']['completeness']}%")

if __name__ == "__main__":
    main()
