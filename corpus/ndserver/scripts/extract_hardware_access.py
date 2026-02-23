#!/usr/bin/env python3
"""
Extract Hardware Register Accesses

Find all Memory-Mapped I/O (MMIO) accesses in the disassembly.
Focus on NeXT hardware registers and NeXTdimension MMIO.

Output: database/hardware_accesses.json
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# Hardware memory ranges
NEXT_HARDWARE_START = 0x02000000
NEXT_HARDWARE_END = 0x02FFFFFF
SYSTEM_DATA_START = 0x04000000
SYSTEM_DATA_END = 0x04FFFFFF
ND_RAM_START = 0xF8000000
ND_RAM_END = 0xFBFFFFFF
ND_VRAM_START = 0xFE000000
ND_VRAM_END = 0xFEFFFFFF
ND_MMIO_START = 0xFF000000
ND_MMIO_END = 0xFFFFFFFF

# Known NeXT hardware registers
NEXT_REGISTERS = {
    0x02000000: 'DMA_CSR',
    0x02004000: 'DMA_CHANNEL_0',
    0x02004010: 'DMA_CHANNEL_1',
    0x02004020: 'DMA_CHANNEL_2',
    0x02004030: 'DMA_CHANNEL_3',
    0x02004040: 'DMA_CHANNEL_4',
    0x02004050: 'DMA_CHANNEL_5',
    0x02004060: 'DMA_CHANNEL_6',
    0x02004070: 'DMA_CHANNEL_7',
    0x02004080: 'DMA_CHANNEL_8',
    0x02004090: 'DMA_CHANNEL_9',
    0x020040a0: 'DMA_CHANNEL_10',
    0x020040b0: 'DMA_CHANNEL_11',
    0x02006000: 'ETHERNET_CSR',
    0x02008000: 'VIDEO_CSR',
    0x0200c000: 'MO_CSR',
    0x0200c800: 'BOARD_CONFIG',
    0x0200e000: 'PRINTER_CSR',
    0x02010000: 'SCC_SERIAL',
    0x02012000: 'DSP_ICR',
    0x02014000: 'SCSI_ESP',
    0x02016000: 'FLOPPY_CONTROLLER',
    0x02018000: 'SOUND_CSR',
    0x0201a000: 'EVENTC_LATCH',
    0x0201c000: 'RTC_NVRAM',
    0x04010000: 'ROM_CONFIG',
    0x04010294: 'SYSTEM_PORT',
}

# Known NeXTdimension registers
ND_REGISTERS = {
    0xF8000000: 'ND_RAM_BASE',
    0xFE000000: 'ND_VRAM_BASE',
    0xFF000000: 'ND_MAILBOX_BASE',
    0xFF200000: 'ND_RAMDAC_BASE',
    0xFF400000: 'ND_DMA_BASE',
    0xFF600000: 'ND_VIDEO_CONTROL',
}

def parse_address(addr_str: str) -> int:
    """Parse hex address string to integer"""
    addr_str = addr_str.strip()
    if addr_str.startswith('0x'):
        return int(addr_str, 16)
    elif addr_str.startswith('(') and addr_str.endswith(').l'):
        # Extract address from (0x1234).l format
        return int(addr_str[1:-3], 16)
    else:
        try:
            return int(addr_str, 16)
        except ValueError:
            return 0

def classify_hardware_access(address: int) -> Tuple[str, str]:
    """
    Classify hardware access by memory range
    Returns: (type, region_name)
    """
    if NEXT_HARDWARE_START <= address <= NEXT_HARDWARE_END:
        return 'NeXT Hardware', 'NEXT_MMIO'
    elif SYSTEM_DATA_START <= address <= SYSTEM_DATA_END:
        return 'System Data', 'SYSTEM_DATA'
    elif ND_RAM_START <= address <= ND_RAM_END:
        return 'NeXTdimension RAM', 'ND_RAM'
    elif ND_VRAM_START <= address <= ND_VRAM_END:
        return 'NeXTdimension VRAM', 'ND_VRAM'
    elif ND_MMIO_START <= address <= ND_MMIO_END:
        return 'NeXTdimension MMIO', 'ND_MMIO'
    else:
        return 'Unknown', 'UNKNOWN'

def get_register_name(address: int) -> str:
    """Get known register name or nearest match"""
    # Check exact match
    if address in NEXT_REGISTERS:
        return NEXT_REGISTERS[address]
    if address in ND_REGISTERS:
        return ND_REGISTERS[address]

    # Find nearest register base
    nearest_name = None
    nearest_dist = float('inf')

    all_registers = {**NEXT_REGISTERS, **ND_REGISTERS}
    for reg_addr, reg_name in all_registers.items():
        dist = abs(address - reg_addr)
        if dist < nearest_dist and dist < 0x1000:  # Within 4KB range
            nearest_dist = dist
            nearest_name = f'{reg_name}+0x{dist:x}'

    return nearest_name if nearest_name else 'UNKNOWN'

def is_memory_access(line: str) -> Tuple[bool, str, str, int]:
    """
    Check if line accesses memory (MOVE, TST, CMP, etc.)
    Returns: (is_access, instruction, operand, address)
    """
    line = line.strip()

    # Match instruction lines
    match = re.match(r'\s*0x([0-9a-fA-F]+):\s+(\w+(?:\.\w+)?)\s+(.+?)(?:\s*;.*)?$', line)
    if not match:
        return False, '', '', 0

    source_addr = int(match.group(1), 16)
    instruction = match.group(2)
    operands = match.group(3)

    # Instructions that access memory
    memory_instructions = [
        'move', 'movem', 'movea', 'tst', 'cmp', 'cmpi', 'cmpa',
        'lea', 'pea', 'clr', 'bset', 'bclr', 'btst',
        'add', 'addi', 'addq', 'sub', 'subi', 'subq',
        'and', 'andi', 'or', 'ori', 'eor', 'eori',
        'not', 'neg', 'asl', 'asr', 'lsl', 'lsr', 'rol', 'ror'
    ]

    instr_base = instruction.split('.')[0].lower()
    if instr_base not in memory_instructions:
        return False, '', '', 0

    # Extract absolute addresses from operands
    # Look for patterns like:
    #   (0x1234).l
    #   move.l  (0x04010294).l,-(SP)
    #   tst.l   (0x02000000).l
    #   lea     (0x81a0).l,A0

    addr_matches = re.findall(r'\(0x([0-9a-fA-F]+)\)\.l', operands)
    for addr_str in addr_matches:
        addr = int(addr_str, 16)
        hw_type, region = classify_hardware_access(addr)
        if hw_type != 'Unknown':
            return True, instruction, operands, addr

    return False, '', '', 0

def load_functions(functions_json: Path) -> Dict[int, dict]:
    """Load function metadata"""
    with open(functions_json) as f:
        functions = json.load(f)

    func_map = {}
    for func in functions:
        addr = func['address']
        func_map[addr] = {
            'address': addr,
            'address_hex': func['address_hex'],
            'name': func['name'],
            'size': func['size']
        }

    return func_map

def parse_disassembly_for_hardware(disasm_file: Path, func_map: Dict[int, dict]) -> Dict[int, List[dict]]:
    """
    Parse disassembly to extract hardware register accesses
    Returns: dict mapping function_address -> list of hardware accesses
    """
    hw_accesses = defaultdict(list)
    current_function = None
    current_function_addr = None

    with open(disasm_file) as f:
        for line in f:
            # Track current function
            if line.startswith('; Function:'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    func_name = parts[1].strip()
                    for addr, func in func_map.items():
                        if func['name'] == func_name:
                            current_function = func
                            current_function_addr = addr
                            break
                continue

            if line.startswith('; Address:'):
                addr_str = line.split(':', 1)[1].strip()
                addr = parse_address(addr_str)
                if addr in func_map:
                    current_function = func_map[addr]
                    current_function_addr = addr
                continue

            # Parse for hardware access
            is_hw, instr, operands, hw_addr = is_memory_access(line)
            if is_hw and current_function_addr:
                # Extract source address from line
                addr_match = re.match(r'\s*0x([0-9a-fA-F]+):', line)
                source_addr = int(addr_match.group(1), 16) if addr_match else 0

                hw_type, region = classify_hardware_access(hw_addr)
                reg_name = get_register_name(hw_addr)

                # Determine access type (read/write)
                access_type = 'read'
                if instr.startswith('move') and operands.split(',')[-1].strip().startswith('(0x'):
                    access_type = 'write'
                elif instr.startswith('clr') or instr.startswith('bset') or instr.startswith('bclr'):
                    access_type = 'write'

                access_info = {
                    'source_address': source_addr,
                    'source_address_hex': f'0x{source_addr:08x}',
                    'hardware_address': hw_addr,
                    'hardware_address_hex': f'0x{hw_addr:08x}',
                    'register_name': reg_name,
                    'type': hw_type,
                    'region': region,
                    'instruction': instr,
                    'operands': operands.strip(),
                    'access_type': access_type
                }

                hw_accesses[current_function_addr].append(access_info)

    return dict(hw_accesses)

def analyze_hardware_usage(hw_accesses: Dict[int, List[dict]], func_map: Dict[int, dict]) -> Dict:
    """Analyze hardware usage patterns"""
    # Group by hardware address
    by_hw_addr = defaultdict(list)
    # Group by region
    by_region = defaultdict(list)
    # Group by register
    by_register = defaultdict(list)

    for func_addr, accesses in hw_accesses.items():
        func_info = func_map.get(func_addr)
        if not func_info:
            continue

        for access in accesses:
            hw_addr = access['hardware_address']
            region = access['region']
            reg_name = access['register_name']

            access_with_func = {
                **access,
                'function_name': func_info['name'],
                'function_address': func_addr,
                'function_address_hex': func_info['address_hex']
            }

            by_hw_addr[hw_addr].append(access_with_func)
            by_region[region].append(access_with_func)
            by_register[reg_name].append(access_with_func)

    return {
        'by_hardware_address': dict(by_hw_addr),
        'by_region': dict(by_region),
        'by_register': dict(by_register)
    }

def main():
    """Main execution"""
    # Paths
    project_root = Path(__file__).parent.parent
    ghidra_dir = project_root / 'ghidra_export'
    db_dir = project_root / 'database'
    db_dir.mkdir(exist_ok=True)

    functions_json = ghidra_dir / 'functions.json'
    disasm_file = ghidra_dir / 'disassembly_full.asm'
    output_file = db_dir / 'hardware_accesses.json'

    print('Extracting Hardware Register Accesses')
    print('=' * 60)

    # Load functions
    print(f'Loading functions from {functions_json}...')
    func_map = load_functions(functions_json)
    print(f'  Found {len(func_map)} functions')

    # Parse disassembly
    print(f'Parsing disassembly for hardware accesses...')
    hw_accesses = parse_disassembly_for_hardware(disasm_file, func_map)
    print(f'  Found {len(hw_accesses)} functions with hardware accesses')

    total_accesses = sum(len(accesses) for accesses in hw_accesses.values())
    print(f'  Total hardware access points: {total_accesses}')

    # Analyze usage
    print('Analyzing hardware usage patterns...')
    analysis = analyze_hardware_usage(hw_accesses, func_map)

    # Count by region
    print()
    print('Hardware Access by Region:')
    for region, accesses in sorted(analysis['by_region'].items()):
        reads = sum(1 for a in accesses if a['access_type'] == 'read')
        writes = sum(1 for a in accesses if a['access_type'] == 'write')
        print(f'  {region:20s}: {len(accesses):3d} accesses ({reads} reads, {writes} writes)')

    # Build output
    output = {
        'metadata': {
            'total_functions': len(func_map),
            'functions_with_hw_access': len(hw_accesses),
            'total_hw_accesses': total_accesses,
            'unique_hw_addresses': len(analysis['by_hardware_address']),
            'unique_registers': len(analysis['by_register'])
        },
        'functions': []
    }

    # Add function entries
    for func_addr in sorted(hw_accesses.keys()):
        func = func_map[func_addr]
        accesses = hw_accesses[func_addr]

        # Count by region for this function
        regions = defaultdict(int)
        for access in accesses:
            regions[access['region']] += 1

        func_entry = {
            'address': func_addr,
            'address_hex': func['address_hex'],
            'name': func['name'],
            'size': func['size'],
            'hardware_accesses': accesses,
            'access_count': len(accesses),
            'regions_accessed': dict(regions)
        }

        output['functions'].append(func_entry)

    # Add analysis
    output['analysis'] = {
        'by_region': {
            region: {
                'count': len(accesses),
                'unique_addresses': len(set(a['hardware_address'] for a in accesses)),
                'accesses': accesses
            }
            for region, accesses in analysis['by_region'].items()
        },
        'by_hardware_address': {
            f'0x{addr:08x}': {
                'address': addr,
                'register_name': accesses[0]['register_name'],
                'type': accesses[0]['type'],
                'access_count': len(accesses),
                'accesses': accesses
            }
            for addr, accesses in analysis['by_hardware_address'].items()
        },
        'by_register': {
            reg_name: {
                'count': len(accesses),
                'unique_functions': len(set(a['function_name'] for a in accesses)),
                'accesses': accesses
            }
            for reg_name, accesses in analysis['by_register'].items()
        }
    }

    # Save output
    print(f'\nSaving hardware accesses to {output_file}...')
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print('Done!')
    print()
    print('Summary:')
    print(f'  Functions with hardware access: {len(hw_accesses)}')
    print(f'  Total hardware access points: {total_accesses}')
    print(f'  Unique hardware addresses: {len(analysis["by_hardware_address"])}')
    print(f'  Unique registers accessed: {len(analysis["by_register"])}')

    # Top accessed registers
    top_registers = sorted(
        analysis['by_register'].items(),
        key=lambda x: -len(x[1])
    )[:10]

    if top_registers:
        print()
        print('Top 10 Most Accessed Registers:')
        for i, (reg_name, info) in enumerate(top_registers, 1):
            print(f'  {i:2d}. {reg_name:30s} - {len(info)} accesses')

if __name__ == '__main__':
    main()
