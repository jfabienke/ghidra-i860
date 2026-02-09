#!/usr/bin/env python3
"""i860 instruction field extraction for analysis scripts.

Encoding: all instructions are 32-bit little-endian.
  bits[31:26] = op6 (primary opcode)
  bits[25:21] = src2
  bits[20:16] = dest
  bits[15:11] = src1
  bits[15:0]  = imm16 (for immediate-form instructions)
  bit[0]      = lsbit0 (size selector for load/store: 0=short, 1=long)

All opcodes verified against SLEIGH source (data/languages/*.sinc).
"""

import struct
from pathlib import Path

# --- Primary opcodes ---
# Load/Store
OP_LD_REG    = 0x04  # ld.{s,l} R1(R2), Rd   (lsbit0: 0=.s, 1=.l)
OP_LD_IMM    = 0x05  # ld.{s,l} simm16(R2), Rd
OP_ST_REG    = 0x06  # st.{s,l} R1, R2(R2src)
OP_ST_IMM    = 0x07  # st.{s,l} R1, stimm(R2)

# Control flow
OP_BRI       = 0x10  # bri R1 (also ret when src1=1)
OP_TRAP      = 0x11
OP_FP_ESC    = 0x12  # FP escape (sub-opcode in bits[6:0])
OP_CORE_ESC  = 0x13  # core escape (sub-opcode in bits[2:0])
OP_BTNE_REG  = 0x14  # btne R1, src2, sbroff
OP_BTNE_IMM  = 0x15  # btne imm5, src2, sbroff
OP_BTE_REG   = 0x16  # bte R1, src2, sbroff
OP_BTE_IMM   = 0x17  # bte imm5, src2, sbroff
OP_BR        = 0x1A  # br offset26
OP_CALL      = 0x1B  # call offset26
OP_BC        = 0x1C  # bc offset26
OP_BC_T      = 0x1D  # bc.t offset26
OP_BNC       = 0x1E  # bnc offset26
OP_BNC_T     = 0x1F  # bnc.t offset26
OP_BLA       = 0x2D  # bla R1, src2, sbroff

# Integer arithmetic
OP_ADDU_REG  = 0x20  # addu R1, R2, Rd
OP_ADDU_IMM  = 0x21  # addu simm16, R2, Rd
OP_SUBU_REG  = 0x22  # subu R1, R2, Rd
OP_SUBU_IMM  = 0x23  # subu simm16, R2, Rd
OP_ADDS_REG  = 0x24  # adds R1, R2, Rd
OP_ADDS_IMM  = 0x25  # adds simm16, R2, Rd
OP_SUBS_REG  = 0x26  # subs R1, R2, Rd
OP_SUBS_IMM  = 0x27  # subs simm16, R2, Rd

# Shifts
OP_SHL_REG   = 0x28  # shl R1, R2, Rd
OP_SHL_IMM   = 0x29  # shl imm16, R2, Rd
OP_SHR_REG   = 0x2A  # shr R1, R2, Rd
OP_SHR_IMM   = 0x2B  # shr imm16, R2, Rd
OP_SHRA_REG  = 0x2E  # shra R1, R2, Rd
OP_SHRA_IMM  = 0x2F  # shra imm16, R2, Rd

# Logic
OP_AND_REG   = 0x30  # and R1, R2, Rd
OP_AND_IMM   = 0x31  # and imm16, R2, Rd
OP_ANDH_IMM  = 0x33  # andh imm16, R2, Rd
OP_ANDNOT_REG = 0x34 # andnot R1, R2, Rd
OP_ANDNOT_IMM = 0x35 # andnot imm16, R2, Rd
OP_ANDNOTH_IMM = 0x37 # andnoth imm16, R2, Rd
OP_OR_REG    = 0x38  # or R1, R2, Rd
OP_OR_IMM    = 0x39  # or imm16, R2, Rd
OP_ORH_IMM   = 0x3B  # orh imm16, R2, Rd
OP_XOR_REG   = 0x3C  # xor R1, R2, Rd
OP_XOR_IMM   = 0x3D  # xor imm16, R2, Rd
OP_XORH_IMM  = 0x3F  # xorh imm16, R2, Rd

# Core escape sub-opcodes (bits[2:0])
ESC_LOCK     = 0x01
ESC_CALLI    = 0x02
ESC_INTOVR   = 0x04
ESC_UNLOCK   = 0x07

# Register names
REG_R0  = 0   # hardwired zero
REG_R1  = 1   # return address (link register)
REG_R2  = 2   # stack pointer (GCC convention)
REG_R3  = 3   # frame pointer (GCC convention)
REG_R15 = 15  # GState base pointer (ND firmware convention)
REG_R28 = 28  # frame pointer (SPEA convention)
REG_R29 = 29  # stack pointer (SPEA convention)


def read_words(path):
    """Read binary file, return list of (offset, word) tuples."""
    data = Path(path).read_bytes()
    words = []
    for i in range(0, len(data) & ~3, 4):
        word = struct.unpack_from('<I', data, i)[0]
        words.append((i, word))
    return words


def read_bytes(path):
    """Read binary file, return raw bytes."""
    return Path(path).read_bytes()


def decode(word):
    """Extract i860 instruction fields from a 32-bit word."""
    imm16_raw = word & 0xFFFF
    return {
        'op6':    (word >> 26) & 0x3F,
        'src2':   (word >> 21) & 0x1F,
        'dest':   (word >> 16) & 0x1F,
        'src1':   (word >> 11) & 0x1F,
        'imm16':  imm16_raw,
        'simm16': imm16_raw - 0x10000 if imm16_raw & 0x8000 else imm16_raw,
        'imm26':  word & 0x3FFFFFF,
        'lsbit0': word & 1,
        'escop':  word & 0x07,
        'fpop':   word & 0x7F,
        'raw':    word,
    }


# --- Instruction predicates ---

def is_orh(d):
    """orh imm16, R2, Rd — sets bits[31:16] of Rd."""
    return d['op6'] == OP_ORH_IMM

def is_or_imm(d):
    """or imm16, R2, Rd — sets bits[15:0] of Rd."""
    return d['op6'] == OP_OR_IMM

def is_or_reg(d):
    return d['op6'] == OP_OR_REG

def is_ld_l_imm(d):
    """ld.l simm16(R2), Rd"""
    return d['op6'] == OP_LD_IMM and d['lsbit0'] == 1

def is_ld_l_reg(d):
    """ld.l R1(R2), Rd"""
    return d['op6'] == OP_LD_REG and d['lsbit0'] == 1

def is_st_l_imm(d):
    """st.l R1, stimm(R2)"""
    return d['op6'] == OP_ST_IMM and d['lsbit0'] == 1

def is_bri(d):
    """bri R1 — indirect branch (excludes ret which has src1=1)."""
    return d['op6'] == OP_BRI and d['src1'] != 1

def is_ret(d):
    return d['op6'] == OP_BRI and d['src1'] == 1

def is_call(d):
    """call offset26 — direct call, target = PC + (offset26 << 2) + 4."""
    return d['op6'] == OP_CALL

def is_calli(d):
    """calli R1 — indirect call."""
    return d['op6'] == OP_CORE_ESC and d['escop'] == ESC_CALLI

def is_br(d):
    """br offset26 — unconditional branch."""
    return d['op6'] == OP_BR

def is_nop(d):
    """All-zeros word (0x00000000) — effectively a nop on i860."""
    return d['raw'] == 0x00000000

def is_and_imm(d):
    """and imm16, R2, Rd — used for type masking."""
    return d['op6'] == OP_AND_IMM

def is_andh_imm(d):
    return d['op6'] == OP_ANDH_IMM

def is_xorh_imm(d):
    return d['op6'] == OP_XORH_IMM

def is_addu_imm(d):
    """addu simm16, R2, Rd — stack frame setup."""
    return d['op6'] == OP_ADDU_IMM

def is_subs_imm(d):
    return d['op6'] == OP_SUBS_IMM


def call_target(addr, d):
    """Compute call/br target: PC + (sext(broff26) << 2).
    From SLEIGH: target = inst_start + (broff26 << 2).  NO +4.
    broff26 is bits[25:0] sign-extended from 26 bits."""
    offset26 = d['imm26']
    if offset26 & 0x2000000:  # sign bit of 26-bit field
        offset26 -= 0x4000000
    return addr + (offset26 << 2)


def sbroff_target(addr, d):
    """Compute split-branch target for bte/btne/bla.
    From SLEIGH: sbrhi = bits[20:16] signed (5 bits), sbrlo = bits[10:0] (11 bits).
    combined = (sbrhi << 11) | sbrlo  (16-bit signed)
    target = inst_start + 4 + combined * 4.  Note: +4 here (unlike br26)."""
    sbrhi = (d['raw'] >> 16) & 0x1F
    if sbrhi & 0x10:  # sign-extend 5-bit field
        sbrhi -= 0x20
    sbrlo = d['raw'] & 0x7FF
    combined = (sbrhi << 11) | sbrlo
    return addr + 4 + (combined * 4)


# --- Convenience: scan for specific patterns ---

def find_orh_r15(words):
    """Find all orh imm16, r15, Rdest instructions (GState field access)."""
    results = []
    for off, word in words:
        d = decode(word)
        if is_orh(d) and d['src2'] == REG_R15:
            results.append((off, d))
    return results


def find_orh_or_pairs(words):
    """Find orh+or pairs that construct 32-bit constants.
    Pattern: orh imm_hi, Rsrc, Rdest  followed by  or imm_lo, Rdest, Rdest
    """
    pairs = []
    for i in range(len(words) - 1):
        off1, w1 = words[i]
        d1 = decode(w1)
        if not is_orh(d1):
            continue
        off2, w2 = words[i + 1]
        d2 = decode(w2)
        if is_or_imm(d2) and d2['src2'] == d1['dest'] and d2['dest'] == d1['dest']:
            value = (d1['imm16'] << 16) | d2['imm16']
            pairs.append({
                'orh_addr': off1,
                'or_addr': off2,
                'src2': d1['src2'],
                'dest': d1['dest'],
                'hi16': d1['imm16'],
                'lo16': d2['imm16'],
                'value': value,
            })
    return pairs


def find_bri(words):
    """Find all bri instructions (indirect branch, not ret)."""
    results = []
    for off, word in words:
        d = decode(word)
        if is_bri(d):
            results.append((off, d))
    return results


def find_calls(words):
    """Find all direct call instructions with resolved targets."""
    results = []
    for off, word in words:
        d = decode(word)
        if is_call(d):
            target = call_target(off, d)
            results.append((off, d, target))
    return results


# --- Phase 2: ABI callee-saved sets ---
GCC_CALLEE_SAVED = set(range(1, 16))       # r1-r15 unaffected across calls
SPEA_CALLEE_SAVED = {1} | set(range(16, 30))  # r1, r16-r29

# --- Phase 2: Delay slot classification ---
# Opcodes with delay slots (+8 to next sequential instruction)
DELAYED_OPS = {OP_BR, OP_CALL, OP_BC_T, OP_BNC_T, OP_BLA, OP_BRI, OP_CORE_ESC}
# CORE_ESC includes calli (escop==2); check escop for calli specifically

# Opcodes without delay slots (+4 to next sequential instruction)
NON_DELAYED_OPS = {OP_BC, OP_BNC, OP_BTE_REG, OP_BTE_IMM, OP_BTNE_REG, OP_BTNE_IMM, OP_TRAP}

# All branch/control flow opcodes
ALL_BRANCH_OPS = DELAYED_OPS | NON_DELAYED_OPS


def is_delayed(d):
    """True if the instruction has a delay slot (next insn executes before branch)."""
    op = d['op6']
    if op in (OP_BR, OP_CALL, OP_BC_T, OP_BNC_T, OP_BLA, OP_BRI):
        return True
    if op == OP_CORE_ESC and d['escop'] == ESC_CALLI:
        return True
    return False


def is_branch(d):
    """True if the instruction is any branch/control-flow instruction."""
    op = d['op6']
    if op in ALL_BRANCH_OPS:
        if op == OP_CORE_ESC:
            return d['escop'] == ESC_CALLI
        return True
    return False


def is_unconditional_branch(d):
    """True for br, bri/ret, call, calli, trap — instructions that always transfer."""
    op = d['op6']
    if op in (OP_BR, OP_CALL, OP_BRI, OP_TRAP):
        return True
    if op == OP_CORE_ESC and d['escop'] == ESC_CALLI:
        return True
    return False


def block_entry_after(addr, d):
    """Compute the fall-through address after a branch instruction.
    Delayed branches: addr + 8 (skip delay slot).
    Non-delayed: addr + 4.
    """
    return addr + 8 if is_delayed(d) else addr + 4


def branch_opname(d):
    """Human-readable name for a branch instruction."""
    op = d['op6']
    names = {
        OP_BR: "br", OP_CALL: "call", OP_BC: "bc", OP_BC_T: "bc.t",
        OP_BNC: "bnc", OP_BNC_T: "bnc.t", OP_BLA: "bla",
        OP_BRI: "bri", OP_TRAP: "trap",
        OP_BTE_REG: "bte", OP_BTE_IMM: "bte",
        OP_BTNE_REG: "btne", OP_BTNE_IMM: "btne",
    }
    if op == OP_CORE_ESC and d['escop'] == ESC_CALLI:
        return "calli"
    return names.get(op, f"op{op:02x}")


def branch_target(addr, d):
    """Compute the branch target for any direct branch instruction.
    Returns None for indirect branches (bri, calli).
    """
    op = d['op6']
    if op in (OP_BR, OP_CALL, OP_BC, OP_BC_T, OP_BNC, OP_BNC_T):
        return call_target(addr, d)
    if op in (OP_BTE_REG, OP_BTE_IMM, OP_BTNE_REG, OP_BTNE_IMM, OP_BLA):
        return sbroff_target(addr, d)
    return None  # bri, calli, trap — no static target


def find_all_branches(words, base_addr=0):
    """Scan all words for branch instructions, return list of branch info dicts.

    Each dict: {offset, addr, opname, target, fall_through, is_delayed, is_conditional}
    target/fall_through are file offsets (not VA).
    """
    binary_size = len(words) * 4
    results = []
    for i, (off, word) in enumerate(words):
        d = decode(word)
        if not is_branch(d):
            continue

        addr = off + base_addr
        target_va = branch_target(addr, d)
        target_off = (target_va - base_addr) if target_va is not None else None

        # Clamp target to binary bounds
        if target_off is not None and (target_off < 0 or target_off >= binary_size):
            target_off = None

        ft = block_entry_after(off, d)
        if ft >= binary_size:
            ft = None

        is_cond = d['op6'] in (OP_BC, OP_BC_T, OP_BNC, OP_BNC_T,
                                OP_BTE_REG, OP_BTE_IMM, OP_BTNE_REG, OP_BTNE_IMM,
                                OP_BLA)

        results.append({
            'offset': off,
            'addr': addr,
            'decoded': d,
            'opname': branch_opname(d),
            'target': target_off,
            'fall_through': ft,
            'is_delayed': is_delayed(d),
            'is_conditional': is_cond,
        })
    return results


def build_reverse_cfg(words, base_addr=0):
    """Build reverse CFG: maps target_offset -> list of predecessor edges.

    Each edge: {source_offset, opname, is_delayed, is_conditional, edge_type}
    edge_type: 'branch_target', 'fall_through', 'call_return', or 'sequential'

    Excludes edges from bri/ret (dynamic) and trap (exception).
    Also builds sequential fall-through edges: if an unconditional branch
    targets offset X, the instruction before the branch's fall-through
    contributes a sequential edge.
    """
    branches = find_all_branches(words, base_addr)
    reverse_cfg = {}  # target_offset -> [edge_info, ...]

    # Track which offsets are unconditional branch terminators (their
    # fall-through starts a new block but has NO sequential predecessor)
    block_terminators = set()  # offsets that end a basic block

    for br in branches:
        opname = br['opname']
        source = br['offset']

        # Mark all branches as block terminators
        block_terminators.add(source)

        # Skip dynamic/exception — no static predecessors
        if opname in ('bri', 'calli', 'trap'):
            continue

        base_edge = {
            'source_offset': source,
            'opname': opname,
            'is_delayed': br['is_delayed'],
            'is_conditional': br['is_conditional'],
        }

        # Edge to branch target
        if br['target'] is not None:
            edge = {**base_edge, 'edge_type': 'branch_target'}
            reverse_cfg.setdefault(br['target'], []).append(edge)

        # Fall-through edge (for conditional branches AND call return)
        if br['is_conditional'] and br['fall_through'] is not None:
            edge = {**base_edge, 'edge_type': 'fall_through'}
            reverse_cfg.setdefault(br['fall_through'], []).append(edge)
        elif opname == 'call' and br['fall_through'] is not None:
            # Call has implicit fall-through (return address)
            edge = {**base_edge, 'edge_type': 'call_return'}
            reverse_cfg.setdefault(br['fall_through'], []).append(edge)

    return reverse_cfg


def writer_input_regs(d):
    """Return list of input register numbers for a dest-writing instruction.

    For register-form ops: [src1, src2] (excluding r0 which is hardwired zero).
    For immediate-form ops: [src2] (the register operand).
    For loads: [src2] (base reg) or [src1, src2] (reg-form load).
    """
    op = d['op6']
    inputs = []

    # Register-form ALU/shift: src1 and src2
    REG_FORM_OPS = {
        OP_ADDU_REG, OP_SUBU_REG, OP_ADDS_REG, OP_SUBS_REG,
        OP_SHL_REG, OP_SHR_REG, OP_SHRA_REG,
        OP_AND_REG, OP_ANDNOT_REG,
        OP_OR_REG, OP_XOR_REG,
    }
    IMM_FORM_OPS = {
        OP_ADDU_IMM, OP_SUBU_IMM, OP_ADDS_IMM, OP_SUBS_IMM,
        OP_SHL_IMM, OP_SHR_IMM, OP_SHRA_IMM,
        OP_AND_IMM, OP_ANDH_IMM,
        OP_ANDNOT_IMM, OP_ANDNOTH_IMM,
        OP_OR_IMM, OP_ORH_IMM,
        OP_XOR_IMM, OP_XORH_IMM,
    }

    if op in REG_FORM_OPS:
        if d['src1'] != 0:
            inputs.append(d['src1'])
        if d['src2'] != 0:
            inputs.append(d['src2'])
    elif op in IMM_FORM_OPS:
        if d['src2'] != 0:
            inputs.append(d['src2'])
    elif op == OP_LD_REG:
        # ld R1(R2), Rd — both src1 (index) and src2 (base) are inputs
        if d['src1'] != 0:
            inputs.append(d['src1'])
        if d['src2'] != 0:
            inputs.append(d['src2'])
    elif op == OP_LD_IMM:
        # ld simm16(R2), Rd — src2 (base) is input
        if d['src2'] != 0:
            inputs.append(d['src2'])

    return inputs


# --- Self-test (run with: python3 i860_decode.py) ---

def self_test():
    """Verify decoder against known instruction encodings from SLEIGH source."""
    import hashlib
    errors = []

    def check(name, got, want):
        if got != want:
            errors.append(f"  FAIL {name}: got {got!r}, want {want!r}")

    # --- 1. Field extraction ---

    # orh 0x1234, r15, r5: op6=0x3B, src2=15, dest=5, imm16=0x1234
    w = (0x3B << 26) | (15 << 21) | (5 << 16) | 0x1234
    d = decode(w)
    check("orh.op6", d['op6'], 0x3B)
    check("orh.src2", d['src2'], 15)
    check("orh.dest", d['dest'], 5)
    check("orh.imm16", d['imm16'], 0x1234)
    check("orh.predicate", is_orh(d), True)

    # or 0x5678, r5, r5: op6=0x39, src2=5, dest=5, imm16=0x5678
    w2 = (0x39 << 26) | (5 << 21) | (5 << 16) | 0x5678
    d2 = decode(w2)
    check("or.op6", d2['op6'], 0x39)
    check("or.src2", d2['src2'], 5)
    check("or.dest", d2['dest'], 5)
    check("or.predicate", is_or_imm(d2), True)

    # bri r8: op6=0x10, src1=8
    w3 = (0x10 << 26) | (8 << 11)
    d3 = decode(w3)
    check("bri.op6", d3['op6'], 0x10)
    check("bri.src1", d3['src1'], 8)
    check("bri.is_bri", is_bri(d3), True)
    check("bri.is_ret", is_ret(d3), False)

    # ret: op6=0x10, src1=1
    w4 = (0x10 << 26) | (1 << 11)
    d4 = decode(w4)
    check("ret.is_bri", is_bri(d4), False)
    check("ret.is_ret", is_ret(d4), True)

    # calli r8: op6=0x13, escop=0x02, src1=8
    w5 = (0x13 << 26) | (8 << 11) | 0x02
    d5 = decode(w5)
    check("calli.predicate", is_calli(d5), True)

    # ld.l 0x10(r15), r7: op6=0x05, lsbit0=1, src2=15, dest=7
    w6 = (0x05 << 26) | (15 << 21) | (7 << 16) | 0x0011  # 0x10 with lsbit0=1
    d6 = decode(w6)
    check("ldl.predicate", is_ld_l_imm(d6), True)
    check("ldl.src2", d6['src2'], 15)
    check("ldl.dest", d6['dest'], 7)

    # and 0xe827, r5, r6: op6=0x31, src2=5, dest=6, imm16=0xe827
    w7 = (0x31 << 26) | (5 << 21) | (6 << 16) | 0xe827
    d7 = decode(w7)
    check("and.predicate", is_and_imm(d7), True)

    # --- 2. Branch target formula (br26) ---
    # SLEIGH: target = inst_start + (broff26 << 2).  NO +4.

    # call at 0x1000, offset=+0x40 → target = 0x1000 + (0x40 << 2) = 0x1100
    wc = (0x1B << 26) | 0x40
    dc = decode(wc)
    check("call.target_fwd", call_target(0x1000, dc), 0x1100)

    # call at 0x2000, offset=-1 → target = 0x2000 + (-1 << 2) = 0x1FFC
    wc2 = (0x1B << 26) | 0x3FFFFFF  # -1 in 26-bit signed
    dc2 = decode(wc2)
    check("call.target_back", call_target(0x2000, dc2), 0x1FFC)

    # br at 0x0000, offset=+1 → target = 0x0000 + (1 << 2) = 0x0004
    wb = (0x1A << 26) | 0x01
    db = decode(wb)
    check("br.target_next", call_target(0x0000, db), 0x0004)

    # --- 3. Split-branch target (sbroff) ---
    # SLEIGH: target = inst_start + 4 + ((sbrhi << 11) | sbrlo) * 4
    # sbrhi = bits[20:16] signed, sbrlo = bits[10:0]

    # bte at 0x1000, sbrhi=0, sbrlo=4 → combined=4, target = 0x1000 + 4 + 16 = 0x1014
    ws = (0x16 << 26) | (0 << 16) | 4  # sbrhi=0, sbrlo=4
    ds = decode(ws)
    check("sbroff.fwd", sbroff_target(0x1000, ds), 0x1014)

    # bte at 0x2000, sbrhi=0x1F (-1), sbrlo=0x7FF → combined = (-1<<11)|0x7FF = -1
    # target = 0x2000 + 4 + (-1 * 4) = 0x2000
    ws2 = (0x16 << 26) | (0x1F << 16) | 0x7FF
    ds2 = decode(ws2)
    check("sbroff.back", sbroff_target(0x2000, ds2), 0x2000)

    # --- 4. orh+or pair constant construction ---
    # orh 0x0001, r0, r5 followed by or 0xFC00, r5, r5 → value = 0x0001FC00
    words = [
        (0x100, (0x3B << 26) | (0 << 21) | (5 << 16) | 0x0001),
        (0x104, (0x39 << 26) | (5 << 21) | (5 << 16) | 0xFC00),
    ]
    pairs = find_orh_or_pairs(words)
    check("pair.count", len(pairs), 1)
    if pairs:
        check("pair.value", pairs[0]['value'], 0x0001FC00)
        check("pair.src2", pairs[0]['src2'], 0)  # r0 = absolute
        check("pair.dest", pairs[0]['dest'], 5)

    # --- 5. Input artifact hash (if clean window exists) ---
    clean_path = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_clean_window.bin")
    if clean_path.exists():
        sha = hashlib.sha256(clean_path.read_bytes()).hexdigest()
        print(f"  clean_window SHA256: {sha}")

    # --- 6. Phase 2: delay slot / branch classification ---

    # br is delayed
    wb_ds = (OP_BR << 26) | 0x01
    db_ds = decode(wb_ds)
    check("br.is_delayed", is_delayed(db_ds), True)
    check("br.is_branch", is_branch(db_ds), True)
    check("br.block_entry_after", block_entry_after(0x100, db_ds), 0x108)

    # bc is NOT delayed
    wbc = (OP_BC << 26) | 0x01
    dbc = decode(wbc)
    check("bc.is_delayed", is_delayed(dbc), False)
    check("bc.block_entry_after", block_entry_after(0x100, dbc), 0x104)

    # bc.t IS delayed
    wbct = (OP_BC_T << 26) | 0x01
    dbct = decode(wbct)
    check("bc.t.is_delayed", is_delayed(dbct), True)

    # calli is delayed
    wcalli = (OP_CORE_ESC << 26) | (8 << 11) | ESC_CALLI
    dcalli = decode(wcalli)
    check("calli.is_delayed", is_delayed(dcalli), True)
    check("calli.is_branch", is_branch(dcalli), True)

    # lock (core_esc but NOT calli) is not a branch
    wlock = (OP_CORE_ESC << 26) | ESC_LOCK
    dlock = decode(wlock)
    check("lock.is_branch", is_branch(dlock), False)

    # writer_input_regs: addu r3, r5, r7 → [3, 5]
    waddu_r = (OP_ADDU_REG << 26) | (5 << 21) | (7 << 16) | (3 << 11)
    daddu_r = decode(waddu_r)
    check("writer_input.addu_reg", writer_input_regs(daddu_r), [3, 5])

    # writer_input_regs: addu 0x10, r5, r7 → [5]
    waddu_i = (OP_ADDU_IMM << 26) | (5 << 21) | (7 << 16) | 0x10
    daddu_i = decode(waddu_i)
    check("writer_input.addu_imm", writer_input_regs(daddu_i), [5])

    # writer_input_regs: or r0, r0, r7 → [] (both r0 excluded)
    wor_zero = (OP_OR_REG << 26) | (0 << 21) | (7 << 16) | (0 << 11)
    dor_zero = decode(wor_zero)
    check("writer_input.or_zero", writer_input_regs(dor_zero), [])

    # ABI sets
    check("gcc_callee.r1", 1 in GCC_CALLEE_SAVED, True)
    check("gcc_callee.r15", 15 in GCC_CALLEE_SAVED, True)
    check("gcc_callee.r16", 16 in GCC_CALLEE_SAVED, False)
    check("spea_callee.r16", 16 in SPEA_CALLEE_SAVED, True)
    check("spea_callee.r15", 15 in SPEA_CALLEE_SAVED, False)

    # --- Report ---
    if errors:
        print(f"FAIL: {len(errors)} self-test error(s):")
        for e in errors:
            print(e)
        return False
    else:
        print("PASS: all decoder self-tests passed")
        return True


if __name__ == '__main__':
    import sys
    ok = self_test()
    sys.exit(0 if ok else 1)
