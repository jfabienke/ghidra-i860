
import re
import sys

def analyze_subroutines(disassembly_file):
    """
    Analyzes an i860 disassembly file to identify subroutines and their intent.
    """
    with open(disassembly_file, 'r') as f:
        lines = f.readlines()

    instructions = []
    for line in lines:
        match = re.match(r'^(0x[0-9a-f]+):\s+([a-zA-Z\.]+)\s+(.*)', line)
        if match:
            address = int(match.group(1), 16)
            mnemonic = match.group(2)
            operands = match.group(3).strip()
            instructions.append({'address': address, 'mnemonic': mnemonic, 'operands': operands, 'line': line.strip()})

    # Find all branch targets to identify potential subroutine starts
    branch_targets = set()
    for instruction in instructions:
        if instruction['mnemonic'].startswith('b') or instruction['mnemonic'] == 'call':
            try:
                # Simple parsing for hex targets
                target_addr_str = instruction['operands'].split(',')[-1].strip()
                if '0x' in target_addr_str:
                    target_addr = int(target_addr_str, 16)
                    branch_targets.add(target_addr)
            except (ValueError, IndexError):
                # Ignore complex operands like registers
                pass

    # Find all 'bri' instructions to identify subroutine ends
    subroutine_ends = []
    for i, instruction in enumerate(instructions):
        if instruction['mnemonic'] == 'bri':
            subroutine_ends.append(i)

    if not subroutine_ends:
        print("No subroutines ending with 'bri' found.")
        return

    # Identify subroutine boundaries
    subroutines = []
    start_index = 0
    for end_index in subroutine_ends:
        # Find the start of the subroutine by looking for a branch target
        # or the instruction after the previous 'bri'
        potential_start = start_index
        for i in range(end_index - 1, start_index, -1):
            if instructions[i]['address'] in branch_targets:
                potential_start = i
                break
        
        subroutines.append(instructions[potential_start:end_index + 1])
        start_index = end_index + 1

    # Analyze each subroutine
    print(f"Found {len(subroutines)} potential subroutines.\n")
    for i, sub in enumerate(subroutines):
        start_addr = sub[0]['address']
        end_addr = sub[-1]['address']
        
        print(f"--- Subroutine {i+1}: 0x{start_addr:08x} - 0x{end_addr:08x} ---")
        
        intent = []
        has_fp = False
        has_call = False
        has_trap = False
        has_ctrl_reg = False

        for instr in sub:
            if instr['mnemonic'].startswith('f'):
                has_fp = True
            if instr['mnemonic'] == 'call':
                has_call = True
            if instr['mnemonic'] == 'trap':
                has_trap = True
            if 'ld.c' in instr['mnemonic'] or 'st.c' in instr['mnemonic']:
                has_ctrl_reg = True
        
        if has_fp:
            intent.append("Floating-point operations")
        if has_call:
            intent.append("Calls other subroutines")
        if has_trap:
            intent.append("System calls (trap)")
        if has_ctrl_reg:
            intent.append("Control register access")
        
        if not intent:
            intent.append("General data manipulation")
            
        print(f"  Intent: {', '.join(intent)}")
        print(f"  Instructions: {len(sub)}")
        print(f"  Starts with: {sub[0]['line']}")
        print(f"  Ends with:   {sub[-1]['line']}")
        print("")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <disassembly_file>")
        sys.exit(1)
    analyze_subroutines(sys.argv[1])
