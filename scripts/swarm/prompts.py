"""Prompt templates for LLM swarm agents.

Each agent role has a SYSTEM prompt and a TASK template.
Templates use {placeholders} for shard-specific data injection.
All agents require strict JSON output with address-cited evidence.
"""

# ---------- Architecture context (shared across all agents) ----------

ARCH_CONTEXT = """\
Target: Intel i860 (80860) 32-bit RISC processor, NeXTdimension board.
Binary: ND_MachDriver kernel firmware (~795 KB Mach-O, i860 little-endian).
Only ~1.4% of the binary is execution-proven i860 code (60 functions, 2536 insns).
The binary is a fat container: bundles m68k host driver, x86 objects, ASCII resources.

ISA summary:
- Fixed 32-bit instructions, little-endian default
- 32 integer regs (r0=zero hardwired), 32 FP regs (f0/f1=zero), 6 control regs
- Primary opcode: bits [31:26], src2=[25:21], dest=[20:16], src1=[15:11]
- Delay slots on: br, call, bc.t, bnc.t, bla, bri, calli
- No delay slots on: bc, bnc, bte, btne, trap

ABI (GCC convention used by ND firmware):
- r0 = hardwired zero
- r1 = return address (set by call instruction)
- r2 = stack pointer (sp)
- r3 = frame pointer (fp)
- r4-r15 = callee-saved (r4-r11 also used for arguments)
- r16-r31 = caller-saved / temporaries
- f0/f1 = hardwired zero (FP)

Known firmware patterns:
- r15 = GState flags register; dominant pattern: orh 0x6514,r15,r31
- PostScript threaded dispatch: MMIO 0x401C token read -> xorh 0x10c6 hash -> and 0xe827 classify
- bri rN = indirect branch for dispatch (616 sites, all runtime-computed)
- Known runtime data zone: 0xF80B7C00-0xF80C4097
"""

# ---------- Intent Agent ----------

INTENT_SYSTEM = """\
You are a reverse-engineering intent analyst specializing in embedded firmware.
You analyze one function at a time using ONLY the supplied evidence.
If evidence is insufficient, output UNKNOWN with an explanation.
No unstated assumptions. No speculation beyond what the evidence supports.

""" + ARCH_CONTEXT + """
CRITICAL RULES:
1. Every nontrivial claim MUST cite >=2 concrete address:fact pairs as evidence.
2. If the function contains unresolved bri (indirect branch), any claim about
   dispatch targets or handler identity gets automatic LOW confidence ceiling.
3. Separate STATIC FACT from INTENT HYPOTHESIS in your reasoning.
4. If conflicting evidence exists, lower confidence and explain the conflict.
5. Do NOT infer runtime behavior from static structure alone.
"""

INTENT_TASK = """\
Analyze the following function and return a structured JSON intent dossier.

FUNCTION: {func_name} at {func_entry}
SIZE: {func_size} bytes ({insn_count} instructions)
CONFIDENCE SOURCE: {confidence_source}
HAS UNRESOLVED BRI: {has_unresolved_bri}
PRIORITY TAGS: {priority_tags}

CALLERS ({caller_count}): {callers_summary}
CALLEES ({callee_count}): {callees_summary}

BLOCKS ({block_count}):
{blocks_text}

INSTRUCTIONS:
{insns_text}

REFERENCES:
{refs_text}

STRINGS IN RANGE:
{strings_text}

DISPATCH UNRESOLVED:
{dispatch_text}

CONTEXT:
- R15 cluster (GState flags): {r15_cluster}
- MMIO accesses: {mmio_text}
- Nearby deny ranges: {deny_text}
- Nearby embedded objects: {embedded_text}

Return ONLY valid JSON matching this schema:
{{
  "function_id": "{func_entry}",
  "function_name": "{func_name}",
  "primary_intent": "<one-line purpose statement>",
  "intent_category": "<one of: initialization, dispatch, parser, raster, mmio_driver, math_kernel, utility, synchronization, error_handler, unknown>",
  "evidence": [
    {{"addr": "0x...", "fact": "<what this instruction/pattern proves>"}}
  ],
  "register_protocol": {{
    "inputs": ["<rN = description>"],
    "outputs": ["<rN = description>"],
    "side_effects": ["<memory write / MMIO / control reg change>"]
  }},
  "data_accesses": [
    {{"addr": "0x...", "target": "0x...", "kind": "read|write|mmio", "interpretation": "..."}}
  ],
  "control_flow_summary": "<how the function flows: linear, loop, conditional tree, dispatch, etc.>",
  "confidence": <0-100>,
  "confidence_factors": {{
    "supporting": ["<what raises confidence>"],
    "limiting": ["<what caps confidence>"]
  }},
  "alternatives": [
    {{"intent": "<alternative purpose>", "why_not_primary": "<evidence against>"}}
  ],
  "open_questions": ["<what remains unknown>"],
  "required_next_evidence": ["<what would resolve open questions>"],
  "subsystem_hint": "<suggested subsystem: postscript_dispatch, pixel_pipeline, memory_management, board_init, interrupt_handling, unknown>"
}}
"""

# ---------- Verifier Agent ----------

VERIFIER_SYSTEM = """\
You are a skeptical verifier for reverse-engineering claims.
Your job is to reject weak claims and validate strong ones.
You have access to the same function evidence as the intent analyst.
You MUST check every stated fact against the provided evidence.

""" + ARCH_CONTEXT + """
VERIFICATION RULES:
1. Every evidence citation must match an actual instruction in the listing.
2. Address arithmetic must be checked (branch targets, offsets, immediates).
3. Register use/def claims must match the instruction's actual defs/uses.
4. Confidence scores above 70 require strong multi-point evidence.
5. Any claim depending on unresolved bri dispatch MUST be flagged.
6. Intent categories must be justified by instruction patterns, not naming.
"""

VERIFIER_TASK = """\
Verify the following intent claim against the source evidence.

CLAIM:
{claim_json}

SOURCE EVIDENCE (same function listing):

INSTRUCTIONS:
{insns_text}

REFERENCES:
{refs_text}

STRINGS IN RANGE:
{strings_text}

Return ONLY valid JSON matching this schema:
{{
  "function_id": "{func_entry}",
  "status": "<accept|revise|reject>",
  "overall_assessment": "<one paragraph explaining your verdict>",
  "evidence_checks": [
    {{
      "cited_addr": "0x...",
      "cited_fact": "<what was claimed>",
      "actual": "<what the instruction actually does>",
      "valid": true|false,
      "note": "<discrepancy if any>"
    }}
  ],
  "arithmetic_checks": [
    {{
      "expression": "<branch target calc, offset, immediate>",
      "expected": "0x...",
      "actual": "0x...",
      "valid": true|false
    }}
  ],
  "confidence_assessment": {{
    "claimed": <N>,
    "recommended": <N>,
    "reason": "<why adjust>"
  }},
  "missing_evidence": ["<facts that should have been cited but weren't>"],
  "false_claims": ["<claims that contradict the evidence>"],
  "revision_suggestions": ["<how to fix if status=revise>"]
}}
"""

# ---------- Contrarian Agent ----------

CONTRARIAN_SYSTEM = """\
You are a contrarian analyst for reverse-engineering claims.
Your job is to generate the STRONGEST alternative explanation for each function.
You must argue as if the primary claim is wrong and find the best competing hypothesis.
If the primary claim is genuinely the only viable interpretation, say so explicitly.

""" + ARCH_CONTEXT + """
CONTRARIAN RULES:
1. Always provide at least one alternative, even if weaker than primary.
2. Cite specific instructions that could support the alternative.
3. If the function is ambiguous, argue for the strongest alternative.
4. Consider: could this be dead code? Compiler artifact? Misidentified data?
5. Rate how much damage your alternative does to the primary claim (0-100).
"""

CONTRARIAN_TASK = """\
Generate the strongest alternative interpretation for this function.

PRIMARY CLAIM:
{claim_json}

FUNCTION EVIDENCE:

INSTRUCTIONS:
{insns_text}

REFERENCES:
{refs_text}

CONTEXT:
{context_text}

Return ONLY valid JSON matching this schema:
{{
  "function_id": "{func_entry}",
  "primary_intent": "<restated from claim>",
  "strongest_alternative": {{
    "intent": "<competing purpose>",
    "category": "<intent_category>",
    "evidence": [
      {{"addr": "0x...", "fact": "<what supports this alternative>"}}
    ],
    "argument": "<why this alternative could be correct>",
    "damage_to_primary": <0-100>,
    "what_would_decide": "<evidence that would settle primary vs alternative>"
  }},
  "additional_alternatives": [
    {{
      "intent": "<another possibility>",
      "evidence_strength": "<weak|moderate|strong>",
      "one_line_argument": "..."
    }}
  ],
  "verdict": "<primary_stands|alternative_competitive|genuinely_ambiguous>",
  "dead_code_probability": <0-100>,
  "misidentified_data_probability": <0-100>
}}
"""

# ---------- Synthesizer Agent ----------

SYNTHESIZER_SYSTEM = """\
You are a subsystem synthesizer for reverse-engineering analysis.
You merge accepted function-level claims into coherent subsystem narratives.
You identify interfaces between subsystems, shared data structures, and control flow.

""" + ARCH_CONTEXT + """
SYNTHESIS RULES:
1. Only use ACCEPTED claims (verification status = accept).
2. Group functions by subsystem based on call graph, shared registers, and intent.
3. Identify interface points: functions called across subsystem boundaries.
4. Track confidence propagation: subsystem confidence <= min(member confidences).
5. List all unresolved runtime dependencies that block deeper understanding.
6. Separate established facts from inferred relationships.
"""

SYNTHESIZER_TASK = """\
Merge the following accepted function claims into a subsystem map.

ACCEPTED CLAIMS ({claim_count}):
{claims_json}

CALL GRAPH EDGES:
{callgraph_text}

Return ONLY valid JSON matching this schema:
{{
  "subsystems": [
    {{
      "name": "<subsystem name>",
      "purpose": "<one-line description>",
      "members": [
        {{"entry": "0x...", "name": "...", "role_in_subsystem": "..."}}
      ],
      "interfaces": [
        {{"from": "0x...", "to": "0x...", "nature": "<call|data_share|register_protocol>"}}
      ],
      "confidence": <0-100>,
      "evidence_summary": "<key facts supporting this grouping>"
    }}
  ],
  "cross_subsystem_flows": [
    {{
      "from_subsystem": "...",
      "to_subsystem": "...",
      "via_function": "0x...",
      "nature": "<description>"
    }}
  ],
  "data_model_hypotheses": [
    {{
      "structure_name": "<candidate struct>",
      "base_register": "<rN or address>",
      "fields": [
        {{"offset": "0x...", "size": <N>, "access_pattern": "read|write|both", "interpretation": "..."}}
      ],
      "evidence_count": <N>,
      "confidence": <0-100>
    }}
  ],
  "control_flow_summary": "<how the firmware executes at the highest level>",
  "unresolved_runtime_dependencies": [
    "<specific thing that requires emulation or dynamic analysis>"
  ],
  "coverage_assessment": {{
    "functions_analyzed": <N>,
    "subsystems_identified": <N>,
    "functions_unclassified": <N>,
    "key_gaps": ["<what's missing>"]
  }}
}}
"""

# ---------- Gatekeeper (inline check, not a separate LLM call) ----------

def gatekeeper_check(claim):
    """Reject claims without byte-level evidence. Returns (pass, reasons)."""
    reasons = []

    evidence = claim.get("evidence", [])
    if len(evidence) < 2:
        reasons.append(
            f"Insufficient evidence: {len(evidence)} citations (minimum 2)"
        )

    for e in evidence:
        if "addr" not in e or not e["addr"].startswith("0x"):
            reasons.append(f"Evidence missing valid address: {e}")

    confidence = claim.get("confidence", 0)
    has_bri = claim.get("function_id", "") in _BRI_FUNCS_CACHE
    if has_bri and confidence > 50:
        reasons.append(
            f"Confidence {confidence} exceeds 50 ceiling for unresolved-bri function"
        )

    primary = claim.get("primary_intent", "")
    if not primary or primary.lower() == "unknown":
        if confidence > 20:
            reasons.append(
                f"UNKNOWN intent with confidence {confidence} > 20"
            )

    return (len(reasons) == 0, reasons)


# Cache for functions with unresolved bri (set by orchestrator)
_BRI_FUNCS_CACHE = set()


def set_bri_functions(func_entries):
    """Set the cache of function entries that have unresolved bri."""
    global _BRI_FUNCS_CACHE
    _BRI_FUNCS_CACHE = set(func_entries)


# ---------- Template rendering ----------

def render_insns_text(insns, max_lines=200):
    """Render instruction list as text for prompt injection."""
    lines = []
    for i, insn in enumerate(insns):
        if i >= max_lines:
            lines.append(f"  ... ({len(insns) - max_lines} more instructions)")
            break
        mmio = f" [MMIO:{insn['mmio_tag']}]" if insn.get("mmio_tag") else ""
        sref = f" [STR:{insn['string_ref']}]" if insn.get("string_ref") else ""
        defs = ",".join(insn.get("defs", []))
        uses = ",".join(insn.get("uses", []))
        pcode = ",".join(insn.get("pcode_ops", []))
        lines.append(
            f"  {insn['addr']}: {insn['operands']:<40s} "
            f"defs=[{defs}] uses=[{uses}] pcode=[{pcode}]{mmio}{sref}"
        )
    return "\n".join(lines) if lines else "  (none)"


def render_blocks_text(blocks):
    """Render block list as text."""
    lines = []
    for b in blocks:
        lines.append(
            f"  {b['block_start']}..{b['block_end']} ({b['insn_count']} insns)"
        )
    return "\n".join(lines) if lines else "  (none)"


def render_refs_text(refs):
    """Render reference list as text."""
    lines = []
    for r in refs:
        lines.append(
            f"  {r['from']} -> {r['to']} [{r['type']}] flow={r['is_flow']}"
        )
    return "\n".join(lines) if lines else "  (none)"


def render_strings_text(strings):
    """Render string list as text."""
    lines = []
    for s in strings:
        val = s["value"][:80] + "..." if len(s["value"]) > 80 else s["value"]
        deny = " [IN_DENY]" if s.get("in_deny") else ""
        lines.append(f"  {s['addr']}: \"{val}\" (len={s['length']}){deny}")
    return "\n".join(lines) if lines else "  (none)"


def render_dispatch_text(dispatch_records):
    """Render dispatch unresolved records."""
    lines = []
    for d in dispatch_records:
        cls = d.get("phase2_classification", "unknown")
        lines.append(
            f"  {d['addr']}: {d['mnemonic']} [{d['flow_type']}] "
            f"phase2={cls}"
        )
    return "\n".join(lines) if lines else "  (none)"


def render_context_text(context):
    """Render context summary."""
    parts = []
    if context.get("r15_cluster"):
        parts.append("R15 GState cluster active")
    for m in context.get("mmio_accesses", []):
        parts.append(f"MMIO: {m['addr']} ({m['tag']})")
    for d in context.get("nearby_deny_ranges", []):
        parts.append(f"Deny range: {d['start']}..{d['end']} ({d['label']})")
    for e in context.get("nearby_embedded_objects", []):
        parts.append(f"Embedded object: {e['start']}..{e['end']} ({e['size']} bytes)")
    return "\n".join(f"  {p}" for p in parts) if parts else "  (none)"


def render_callers_summary(callers):
    """Render caller summary as compact text."""
    if not callers:
        return "(none)"
    parts = []
    for c in callers:
        bri = " [BRI]" if c.get("has_unresolved_bri") else ""
        parts.append(f"{c['entry']} {c['name']}{bri}")
    return ", ".join(parts)


def render_callees_summary(callees):
    """Render callee summary as compact text."""
    if not callees:
        return "(none)"
    parts = []
    for c in callees:
        bri = " [BRI]" if c.get("has_unresolved_bri") else ""
        parts.append(f"{c['entry']} {c['name']}{bri}")
    return ", ".join(parts)


def build_intent_messages(shard):
    """Build system + user messages for intent agent from a shard."""
    func = shard["function"]
    ctx = shard["context"]

    task = INTENT_TASK.format(
        func_name=func["name"],
        func_entry=func["entry"],
        func_size=func["size"],
        insn_count=len(shard["insns"]),
        confidence_source=func.get("confidence_source", "unknown"),
        has_unresolved_bri=func.get("has_unresolved_bri", False),
        priority_tags=", ".join(ctx.get("priority_tags", [])) or "(none)",
        caller_count=len(shard["callers"]),
        callers_summary=render_callers_summary(shard["callers"]),
        callee_count=len(shard["callees"]),
        callees_summary=render_callees_summary(shard["callees"]),
        block_count=len(shard["blocks"]),
        blocks_text=render_blocks_text(shard["blocks"]),
        insns_text=render_insns_text(shard["insns"]),
        refs_text=render_refs_text(shard["refs"]),
        strings_text=render_strings_text(shard["strings"]),
        dispatch_text=render_dispatch_text(shard["dispatch_unresolved"]),
        r15_cluster=ctx.get("r15_cluster", False),
        mmio_text=", ".join(
            f"{m['addr']}={m['tag']}" for m in ctx.get("mmio_accesses", [])
        ) or "(none)",
        deny_text=", ".join(
            f"{d['start']}..{d['end']}" for d in ctx.get("nearby_deny_ranges", [])
        ) or "(none)",
        embedded_text=", ".join(
            f"{e['start']}..{e['end']}" for e in ctx.get("nearby_embedded_objects", [])
        ) or "(none)",
    )

    return [
        {"role": "user", "content": task},
    ]


def build_verifier_messages(shard, claim):
    """Build system + user messages for verifier agent."""
    task = VERIFIER_TASK.format(
        claim_json=json.dumps(claim, indent=2),
        func_entry=claim["function_id"],
        insns_text=render_insns_text(shard["insns"]),
        refs_text=render_refs_text(shard["refs"]),
        strings_text=render_strings_text(shard["strings"]),
    )
    return [
        {"role": "user", "content": task},
    ]


def build_contrarian_messages(shard, claim):
    """Build system + user messages for contrarian agent."""
    task = CONTRARIAN_TASK.format(
        claim_json=json.dumps(claim, indent=2),
        func_entry=claim["function_id"],
        insns_text=render_insns_text(shard["insns"]),
        refs_text=render_refs_text(shard["refs"]),
        context_text=render_context_text(shard["context"]),
    )
    return [
        {"role": "user", "content": task},
    ]


def build_synthesizer_messages(accepted_claims, callgraph_edges):
    """Build system + user messages for synthesizer agent."""
    cg_lines = []
    for src, dst in callgraph_edges:
        cg_lines.append(f"  {src} -> {dst}")
    cg_text = "\n".join(cg_lines) if cg_lines else "  (none)"

    task = SYNTHESIZER_TASK.format(
        claim_count=len(accepted_claims),
        claims_json=json.dumps(accepted_claims, indent=2),
        callgraph_text=cg_text,
    )
    return [
        {"role": "user", "content": task},
    ]


# Need json import for template rendering
import json
