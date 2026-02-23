#!/usr/bin/env python3
"""
Analyze isolated functions from NDserver driver
Categorize by purpose and priority for reverse engineering
"""

import json
import re
from typing import Dict, List, Set
from datetime import datetime

# Category definitions
CATEGORIES = {
    'Callback': 'Signal handlers, event callbacks, function pointers',
    'Error/Logging': 'Printf/fprintf/syslog, error messages',
    'Utility/Helper': 'String manipulation, math, data structures',
    'Hardware': 'Direct register access, MMIO, DMA',
    'Initialization': 'One-time setup, global initialization',
    'IPC/Protocol': 'Mach messages, network, serialization',
    'i860 Communication': 'Mailbox, shared memory, i860-specific',
    'Dead Code': 'Unreferenced, obsolete patterns',
    'Unknown': 'Insufficient information to categorize'
}

PRIORITY_LEVELS = ['Critical', 'High', 'Medium', 'Low']
COMPLEXITY_LEVELS = ['High', 'Medium', 'Low']


class IsolatedFunctionAnalyzer:
    def __init__(self):
        self.analyzed_functions = []
        self.all_functions = []
        self.isolated_functions = []
        self.decompiled_code = ""

    def load_data(self):
        """Load all necessary data files"""
        with open('database/analysis_order.json', 'r') as f:
            self.analyzed_functions = json.load(f)

        with open('ghidra_export/functions.json', 'r') as f:
            self.all_functions = json.load(f)

        with open('ghidra_export/disassembly_full.asm', 'r') as f:
            self.decompiled_code = f.read()

        # Identify isolated functions
        analyzed_addrs = set(f['address'] for f in self.analyzed_functions)
        self.isolated_functions = [f for f in self.all_functions if f['address'] not in analyzed_addrs]

        print(f"Loaded {len(self.all_functions)} total functions")
        print(f"Found {len(self.isolated_functions)} isolated functions")

    def extract_function_code(self, func_name: str, func_addr: str) -> str:
        """Extract assembly code for a specific function"""
        # Look for function header: ; Function: FUN_XXXXXXXX
        pattern = rf'; Function: {re.escape(func_name)}\n'

        match = re.search(pattern, self.decompiled_code)

        if not match:
            return ""

        start_pos = match.start()

        # Find next function (starts with ; Function:)
        next_func = re.search(r'\n; Function: ',
                             self.decompiled_code[start_pos + 20:])

        if next_func:
            end_pos = start_pos + 20 + next_func.start()
        else:
            # Take next 3000 chars max
            end_pos = min(start_pos + 3000, len(self.decompiled_code))

        return self.decompiled_code[start_pos:end_pos]

    def analyze_function(self, func_info: Dict) -> Dict:
        """Analyze a single isolated function"""
        func_name = func_info['name']
        func_addr = func_info['address_hex']
        func_size = func_info['size']

        # Extract code
        code = self.extract_function_code(func_name, func_addr)

        # Initialize analysis result
        result = {
            'address': func_addr,
            'address_decimal': func_info['address'],
            'name': func_name,
            'size': func_size,
            'categories': [],
            'priority': 'Medium',  # Default
            'complexity': 'Medium',  # Default
            'reasoning': '',
            'key_evidence': [],
            'suggested_name': func_name,
            'recommended_analysis_wave': 5
        }

        # Determine complexity based on size
        if func_size >= 500:
            result['complexity'] = 'High'
        elif func_size < 100:
            result['complexity'] = 'Low'

        if not code:
            result['categories'].append('Unknown')
            result['reasoning'] = 'Could not extract decompiled code'
            result['priority'] = 'Low'
            return result

        # Pattern detection for assembly code
        evidence = []
        categories = set()

        # Count external function calls (0x0500xxxx addresses)
        external_calls = re.findall(r'(?:jsr|bsr)\.[bwl]?\s+0x0500[0-9a-fA-F]{4}', code, re.IGNORECASE)
        num_external_calls = len(external_calls)

        if num_external_calls > 0:
            evidence.append(f'Makes {num_external_calls} external function call(s)')

        # Check for specific library function patterns (would need symbol table, but try common patterns)
        # For now, classify based on structural patterns

        # Check for stack frame setup
        has_link = bool(re.search(r'\blink\.[bwl]\s+A6', code, re.IGNORECASE))
        has_movem = bool(re.search(r'\bmovem\.[bwl]\s+', code, re.IGNORECASE))

        if has_link:
            evidence.append('Has stack frame (link instruction)')

        if has_movem:
            evidence.append('Saves/restores multiple registers')

        # Check for hardware register access (0x02000000, 0x01000000, or 0x04000000 range)
        hw_accesses = re.findall(r'0x0[1-4][0-9a-fA-F]{6}', code, re.IGNORECASE)
        if hw_accesses:
            categories.add('Hardware')
            unique_addrs = list(set(hw_accesses))[:3]  # First 3 unique
            evidence.append(f'Accesses {len(hw_accesses)} hardware/memory address(es): {", ".join(unique_addrs)}')

        # Check for loop structures (indicates computation/processing)
        has_loop = bool(re.search(r'\b(dbra|dbf|dbeq|dbne)\b', code, re.IGNORECASE))
        has_branch_back = bool(re.search(r'\bb(ra|eq|ne|lt|gt|le|ge)\.[bwl]?\s+0x[0-9a-f]{4,8}', code, re.IGNORECASE))

        if has_loop:
            evidence.append('Contains loop (dbxx instruction)')
            categories.add('Utility/Helper')

        # Check for conditional branches (complex logic)
        num_branches = len(re.findall(r'\bb(eq|ne|lt|gt|le|ge|cc|cs|mi|pl|vs|vc)\.[bwl]?', code, re.IGNORECASE))
        if num_branches >= 3:
            evidence.append(f'Has {num_branches} conditional branches')

        # Check for PC-relative data access (string constants, tables)
        pc_relative = re.findall(r'(?:pea|lea|move\.[bwl])\s+\([^)]*,pc\)', code, re.IGNORECASE)
        if pc_relative:
            evidence.append(f'Accesses {len(pc_relative)} PC-relative data item(s)')
            # PC-relative often means string or constant table access
            if num_external_calls > 0:
                categories.add('Error/Logging')  # Likely printf-style with format string

        # Check for trap instructions (Mach system calls)
        if re.search(r'\btrap\s+#', code, re.IGNORECASE):
            categories.add('IPC/Protocol')
            evidence.append('Uses trap instruction (Mach system call)')

        # Classify based on size and complexity
        if func_size < 50:
            if num_external_calls == 0 and not has_link:
                categories.add('Dead Code')
                evidence.append('Very small, no stack frame, no external calls')
        elif func_size > 250:
            # Large functions are usually operational
            if not categories or 'Dead Code' in categories:
                categories.discard('Dead Code')
                categories.add('Unknown')
                evidence.append('Large function (likely operational)')

        # Classify based on call patterns
        if num_external_calls >= 3:
            # Functions with many external calls are usually high-level logic
            categories.add('Utility/Helper')
            if len(pc_relative) > 0:
                categories.add('Error/Logging')  # Likely error reporting with multiple calls

        # Check for typical callback signatures (minimal stack, quick return)
        if has_link and func_size < 150 and num_external_calls <= 2:
            categories.add('Callback')
            evidence.append('Small function with stack frame (callback pattern)')

        # Similar-sized functions in sequence might be dispatch table entries
        # (We'll detect this in the post-processing phase)

        # If no categories found
        if not categories:
            categories.add('Unknown')
            evidence.append('No clear patterns detected')

        result['categories'] = sorted(list(categories))
        result['key_evidence'] = evidence

        # Determine priority
        if 'Callback' in categories or 'Hardware' in categories:
            result['priority'] = 'High'
        elif 'Error/Logging' in categories or 'IPC/Protocol' in categories:
            result['priority'] = 'High'
        elif 'i860 Communication' in categories:
            result['priority'] = 'Critical'
        elif 'Dead Code' in categories:
            result['priority'] = 'Low'
        elif 'Unknown' in categories and func_size < 100:
            result['priority'] = 'Low'

        # Build reasoning
        result['reasoning'] = f"Size: {func_size} bytes. " + '. '.join(evidence)

        # Suggest better name if possible
        if 'Callback' in categories and 'signal' in code.lower():
            result['suggested_name'] = f'SignalHandler_{func_addr}'
        elif 'Error/Logging' in categories:
            result['suggested_name'] = f'ErrorLog_{func_addr}'
        elif 'Hardware' in categories:
            result['suggested_name'] = f'HardwareAccess_{func_addr}'

        return result

    def categorize_all(self) -> List[Dict]:
        """Categorize all isolated functions"""
        results = []

        for func in self.isolated_functions:
            print(f"Analyzing {func['name']} ({func['address_hex']})...")
            result = self.analyze_function(func)
            results.append(result)

        return results

    def generate_json_report(self, results: List[Dict]) -> Dict:
        """Generate JSON categorization report"""
        # Group by category
        by_category = {}
        for cat in CATEGORIES.keys():
            by_category[cat] = []

        for func in results:
            for cat in func['categories']:
                if cat in by_category:
                    by_category[cat].append(func['address'])

        # Group by priority
        by_priority = {p: [] for p in PRIORITY_LEVELS}
        for func in results:
            by_priority[func['priority']].append(func['address'])

        report = {
            'metadata': {
                'total_isolated': len(results),
                'analysis_date': datetime.now().strftime('%Y-%m-%d'),
                'categories_used': list(CATEGORIES.keys()),
                'confidence_note': 'Based on static analysis without runtime traces'
            },
            'by_category': by_category,
            'by_priority': by_priority,
            'functions': results
        }

        return report

    def generate_markdown_report(self, results: List[Dict]) -> str:
        """Generate human-readable markdown report"""
        md = []

        md.append("# Isolated Functions Categorization Report")
        md.append(f"\nAnalysis Date: {datetime.now().strftime('%Y-%m-%d')}")
        md.append(f"\nTotal Isolated Functions: {len(results)}")
        md.append("\n---\n")

        # Executive Summary
        md.append("## Executive Summary\n")

        # Category distribution
        cat_counts = {}
        for func in results:
            for cat in func['categories']:
                cat_counts[cat] = cat_counts.get(cat, 0) + 1

        md.append("### Category Distribution\n")
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            md.append(f"- **{cat}**: {count} functions")

        md.append("\n### Priority Distribution\n")
        priority_counts = {}
        for func in results:
            priority_counts[func['priority']] = priority_counts.get(func['priority'], 0) + 1

        for priority in PRIORITY_LEVELS:
            count = priority_counts.get(priority, 0)
            md.append(f"- **{priority}**: {count} functions")

        # Top 10 priority functions
        md.append("\n---\n## Top 10 Priority Functions to Analyze Next\n")

        # Sort by priority then size
        priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_funcs = sorted(results,
                            key=lambda x: (priority_order[x['priority']], -x['size']))

        md.append("| Address | Size | Priority | Categories | Reasoning |")
        md.append("|---------|------|----------|------------|-----------|")

        for func in sorted_funcs[:10]:
            cats = ', '.join(func['categories'])
            reasoning = func['reasoning'][:80] + '...' if len(func['reasoning']) > 80 else func['reasoning']
            md.append(f"| {func['address']} | {func['size']}B | {func['priority']} | {cats} | {reasoning} |")

        # Full function table
        md.append("\n---\n## All Functions Sorted by Priority\n")

        for priority in PRIORITY_LEVELS:
            funcs = [f for f in sorted_funcs if f['priority'] == priority]
            if not funcs:
                continue

            md.append(f"\n### {priority} Priority ({len(funcs)} functions)\n")
            md.append("| Address | Name | Size | Categories | Key Evidence |")
            md.append("|---------|------|------|------------|--------------|")

            for func in funcs:
                cats = ', '.join(func['categories'])
                evidence = func['key_evidence'][0] if func['key_evidence'] else 'None'
                md.append(f"| {func['address']} | {func['name']} | {func['size']}B | {cats} | {evidence} |")

        # Category insights
        md.append("\n---\n## Category-Specific Insights\n")

        for cat in sorted(cat_counts.keys()):
            if cat_counts[cat] == 0:
                continue

            funcs = [f for f in results if cat in f['categories']]
            md.append(f"\n### {cat} ({len(funcs)} functions)\n")
            md.append(f"**Description**: {CATEGORIES[cat]}\n")

            # List functions in this category
            for func in funcs[:5]:  # Top 5
                md.append(f"- **{func['address']}** ({func['size']}B): {func['reasoning']}")

            if len(funcs) > 5:
                md.append(f"- ... and {len(funcs) - 5} more")

        # Recommended waves
        md.append("\n---\n## Recommended Analysis Waves\n")
        md.append("\nFunctions grouped by category and priority for systematic analysis:\n")

        wave_num = 5  # Start at wave 5 (after current analyzed functions)

        # Wave 1: Critical priority
        critical = [f for f in sorted_funcs if f['priority'] == 'Critical']
        if critical:
            md.append(f"\n### Wave {wave_num}: Critical i860 Communication ({len(critical)} functions)")
            for func in critical:
                md.append(f"- {func['address']} - {func['name']}")
            wave_num += 1

        # Wave 2: High priority callbacks and hardware
        high = [f for f in sorted_funcs if f['priority'] == 'High' and
                ('Callback' in f['categories'] or 'Hardware' in f['categories'])]
        if high:
            md.append(f"\n### Wave {wave_num}: High Priority Callbacks & Hardware ({len(high)} functions)")
            for func in high[:15]:  # Max 15 per wave
                md.append(f"- {func['address']} - {func['name']}")
            wave_num += 1

        # Wave 3: Error/Logging and IPC
        comm = [f for f in sorted_funcs if f['priority'] == 'High' and
                ('Error/Logging' in f['categories'] or 'IPC/Protocol' in f['categories'])]
        if comm:
            md.append(f"\n### Wave {wave_num}: Error Handling & IPC ({len(comm)} functions)")
            for func in comm[:15]:
                md.append(f"- {func['address']} - {func['name']}")
            wave_num += 1

        # Wave 4: Utilities
        utils = [f for f in sorted_funcs if f['priority'] == 'Medium' and
                 'Utility/Helper' in f['categories']]
        if utils:
            md.append(f"\n### Wave {wave_num}: Utility Functions ({len(utils)} functions)")
            for func in utils[:15]:
                md.append(f"- {func['address']} - {func['name']}")
            wave_num += 1

        # Wave 5: Unknown/remaining
        remaining = [f for f in sorted_funcs if f['priority'] in ['Medium', 'Low'] and
                    'Unknown' in f['categories']]
        if remaining:
            md.append(f"\n### Wave {wave_num}: Unknown/Low Priority ({len(remaining)} functions)")
            md.append("\nRecommend analyzing these after waves 1-4 provide more context.")

        # Confidence assessment
        md.append("\n---\n## Confidence Assessment\n")

        high_conf = len([f for f in results if 'Unknown' not in f['categories']])
        low_conf = len([f for f in results if 'Unknown' in f['categories'] and len(f['categories']) == 1])
        mixed_conf = len(results) - high_conf - low_conf

        confidence_pct = (high_conf / len(results)) * 100

        md.append(f"- **High Confidence** (clear categorization): {high_conf} functions ({confidence_pct:.1f}%)")
        md.append(f"- **Medium Confidence** (multiple categories): {mixed_conf} functions")
        md.append(f"- **Low Confidence** (unknown only): {low_conf} functions")

        md.append("\n---\n## Surprising Findings\n")

        # Look for patterns
        large_unknown = [f for f in results if 'Unknown' in f['categories'] and f['size'] > 200]
        if large_unknown:
            md.append(f"\n- **Large unknown functions**: {len(large_unknown)} functions >200 bytes with unclear purpose")
            md.append("  - Recommend manual inspection of these")

        # Check for function families (consecutive addresses)
        families = []
        prev_addr = -1000
        current_family = []
        for func in sorted(results, key=lambda x: x['address_decimal']):
            if func['address_decimal'] - prev_addr < 500:  # Within 500 bytes
                current_family.append(func)
            else:
                if len(current_family) >= 3:
                    families.append(current_family)
                current_family = [func]
            prev_addr = func['address_decimal']

        if len(current_family) >= 3:
            families.append(current_family)

        if families:
            md.append(f"\n- **Function families detected**: {len(families)} groups of related functions")
            for i, family in enumerate(families[:3], 1):
                addrs = [f['address'] for f in family]
                md.append(f"  - Family {i}: {', '.join(addrs[:5])} ({len(family)} functions)")

        return '\n'.join(md)


def main():
    analyzer = IsolatedFunctionAnalyzer()

    print("Loading data...")
    analyzer.load_data()

    print(f"\nCategorizing {len(analyzer.isolated_functions)} isolated functions...")
    results = analyzer.categorize_all()

    print("\nGenerating reports...")

    # JSON report
    json_report = analyzer.generate_json_report(results)
    with open('database/isolated_functions_categorization.json', 'w') as f:
        json.dump(json_report, f, indent=2)
    print("✓ Generated database/isolated_functions_categorization.json")

    # Markdown report
    md_report = analyzer.generate_markdown_report(results)
    with open('docs/ISOLATED_FUNCTIONS_CATEGORIZATION.md', 'w') as f:
        f.write(md_report)
    print("✓ Generated docs/ISOLATED_FUNCTIONS_CATEGORIZATION.md")

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    cat_counts = {}
    for func in results:
        for cat in func['categories']:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    print("\nCategory Distribution:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    priority_counts = {}
    for func in results:
        priority_counts[func['priority']] = priority_counts.get(func['priority'], 0) + 1

    print("\nPriority Distribution:")
    for priority in ['Critical', 'High', 'Medium', 'Low']:
        count = priority_counts.get(priority, 0)
        print(f"  {priority}: {count}")

    high_conf = len([f for f in results if 'Unknown' not in f['categories']])
    confidence_pct = (high_conf / len(results)) * 100

    print(f"\nConfidence: {confidence_pct:.1f}% ({high_conf}/{len(results)} functions)")

    print("\n" + "="*60)


if __name__ == '__main__':
    main()
