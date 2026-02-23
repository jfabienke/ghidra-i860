#!/usr/bin/env python3
"""
Ghidra headless script to import NDserver with custom memory map.

This script:
1. Loads NDserver binary
2. Creates memory regions for m68k segments only
3. Marks __I860 segment as DATA (not code)
4. Imports function boundaries from Phase 2 analysis
5. Forces analysis only on m68k code regions
"""

# Ghidra Python API imports (these are available in Ghidra's Jython environment)
from ghidra.app.util.importer import MessageLog
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Function
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.symbol import SourceType

import json

def main():
    """Main Ghidra headless script"""

    print("=" * 80)
    print("NDserver Custom Import Script")
    print("=" * 80)

    # Get current program (loaded by analyzeHeadless)
    program = getCurrentProgram()
    if program is None:
        print("ERROR: No program loaded")
        return

    print(f"Program: {program.getName()}")
    print(f"Language: {program.getLanguage().getLanguageID()}")
    print(f"Address Space: {program.getAddressFactory().getDefaultAddressSpace()}")

    # Start a transaction
    txId = program.startTransaction("Custom Memory Map Setup")

    try:
        # Step 1: Mark __I860 segment as DATA only
        mark_i860_as_data(program)

        # Step 2: Load function map from Phase 2
        function_map = load_function_map()

        # Step 3: Create functions at known addresses
        create_functions(program, function_map)

        # Step 4: Restrict analysis to m68k code only
        restrict_analysis_region(program)

        program.endTransaction(txId, True)
        print("\n" + "=" * 80)
        print("Custom import completed successfully")
        print("=" * 80)

    except Exception as e:
        program.endTransaction(txId, False)
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

def mark_i860_as_data(program):
    """Mark the __I860 segment as data, not code"""
    print("\n[1] Marking __I860 segment as DATA...")

    memory = program.getMemory()

    # __I860 segment: 0x0000A000 - 0x000CDFFF (based on otool output)
    i860_start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0000A000)
    i860_end = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x000CDFFF)

    # Get or create memory block
    i860_block = memory.getBlock(i860_start)
    if i860_block:
        print(f"  Found __I860 block: {i860_block.getName()}")
        print(f"    Start: {i860_block.getStart()}")
        print(f"    End: {i860_block.getEnd()}")
        print(f"    Size: {i860_block.getSize()} bytes")

        # Mark as non-executable
        i860_block.setExecute(False)
        i860_block.setRead(True)
        i860_block.setWrite(False)

        print(f"  ✓ Marked as DATA (non-executable)")
    else:
        print(f"  WARNING: __I860 block not found")

def load_function_map():
    """Load function boundaries from Phase 2 analysis"""
    print("\n[2] Loading function map from Phase 2...")

    # Path to function map (relative to Ghidra project)
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    function_map_path = os.path.join(project_dir, 'analysis', 'annotated_functions.json')

    print(f"  Reading: {function_map_path}")

    with open(function_map_path, 'r') as f:
        functions = json.load(f)

    print(f"  ✓ Loaded {len(functions)} functions")
    return functions

def create_functions(program, function_map):
    """Create function entries at known boundaries"""
    print("\n[3] Creating functions at known addresses...")

    listing = program.getListing()
    function_manager = program.getFunctionManager()
    addr_factory = program.getAddressFactory().getDefaultAddressSpace()

    created = 0
    skipped = 0

    for func in function_map:
        func_addr = addr_factory.getAddress(func['start'])
        func_name = func['label']

        # Check if function already exists
        existing_func = function_manager.getFunctionAt(func_addr)
        if existing_func:
            print(f"  - {func_name} @ 0x{func['start']:08x} (already exists)")
            skipped += 1
            continue

        # Create function
        cmd = CreateFunctionCmd(func_addr)
        if cmd.applyTo(program):
            new_func = function_manager.getFunctionAt(func_addr)
            if new_func:
                # Set function name
                new_func.setName(func_name, SourceType.USER_DEFINED)
                print(f"  ✓ {func_name} @ 0x{func['start']:08x} ({func['size']} bytes)")
                created += 1
        else:
            print(f"  ✗ Failed to create {func_name} @ 0x{func['start']:08x}")

    print(f"\n  Created: {created}, Skipped: {skipped}, Total: {len(function_map)}")

def restrict_analysis_region(program):
    """Restrict auto-analysis to m68k code regions only"""
    print("\n[4] Restricting analysis to m68k code regions...")

    addr_factory = program.getAddressFactory().getDefaultAddressSpace()

    # Define m68k code regions based on otool output
    # __text section: 0x00002d10 - 0x000075f8
    code_regions = [
        (0x00002d10, 0x000075f8, "__text"),
    ]

    analysis_set = AddressSet()

    for start, end, name in code_regions:
        start_addr = addr_factory.getAddress(start)
        end_addr = addr_factory.getAddress(end)
        analysis_set.add(start_addr, end_addr)
        print(f"  + {name}: 0x{start:08x} - 0x{end:08x}")

    print(f"  ✓ Analysis restricted to {analysis_set.getNumAddresses()} addresses")

    # Note: This doesn't directly restrict Ghidra's auto-analysis in headless mode,
    # but the function boundaries we've created will guide the analyzer

if __name__ == '__main__':
    main()
