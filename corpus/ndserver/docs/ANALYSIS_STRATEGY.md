# Analysis Strategy: Bottom-Up Approach

**Question**: What is the best sequence of attack?
**Answer**: **Leaf nodes first, then work up the call graph** ✅

---

## Why Bottom-Up?

### 1. **Dependencies Flow Downward**
```
ND_GetBoardList()
  └─> ND_LookupBoardBySlot()  ← Leaf (no calls)
      └─> global_slot_table
```

- **Leaf function** (ND_LookupBoardBySlot): Simple lookup, easy to understand
- **Parent function** (ND_GetBoardList): Complex, but makes sense once you understand what the leaf does

**If we analyze top-down**:
- See call to ND_LookupBoardBySlot, but don't know what it does
- Have to guess or make assumptions
- May misunderstand parent function's behavior

**If we analyze bottom-up**:
- Understand ND_LookupBoardBySlot first (simple, self-contained)
- When we reach ND_GetBoardList, we already know what lookup does
- Parent function analysis is faster and more accurate

---

### 2. **Leaf Nodes Are Simpler**

**Leaf function characteristics**:
- No BSR/JSR calls (self-contained)
- Small code size (usually <100 bytes)
- Clear purpose (one job only)
- Easy to reverse-engineer to C

**Example - FUN_00003820 (leaf)**:
- 84 bytes, 21 instructions
- Pure data structure lookup
- Reverse-engineered in 30 minutes

**Root function characteristics**:
- Many subcalls (complex flow)
- Large code size (hundreds of bytes)
- Multiple responsibilities
- Requires understanding all callees first

**Example - ND_GetBoardList (root)**:
- 662 bytes, ~150 instructions
- Calls 10+ functions
- Would take hours without understanding leaves

---

### 3. **Data Structure Discovery**

Bottom-up naturally reveals data structures:

**Step 1: Analyze leaf** `ND_LookupBoardBySlot`:
```c
struct board_info {
    uint32_t board_id;    // +0x00
    void*    data_ptr;    // +0x04
};
```

**Step 2: Analyze parent** `ND_GetBoardList`:
```c
// Now we know board_info structure exists
// Can recognize when parent allocates/populates it
```

**Top-down would miss this** - we'd see memory accesses without context.

---

### 4. **Library Call Identification**

Leaf functions often wrap library calls:

```
FUN_00003820 (pure logic, no libs)
    ^
    |
FUN_00002DC6 (calls printf, malloc, port_allocate)
    ^
    |
main/entry (orchestrates everything)
```

Bottom-up lets us:
1. Understand pure logic first
2. Identify library wrappers next
3. Understand high-level flow last

---

## Attack Plan: Phased Bottom-Up Analysis

### Phase A: Foundation (Automated)

**Goal**: Build call graph metadata

**Tasks**:
1. Extract all functions from Ghidra output
2. Build call graph (who calls whom)
3. Calculate graph depth for each function
4. Identify leaf nodes (no outgoing calls)
5. Classify by layer

**Output**:
```json
{
  "address": "0x00003820",
  "name": "FUN_00003820",
  "depth": 0,  // Leaf node
  "calls": [],  // No outgoing calls
  "called_by": ["0x00002dc6", "0x00003284"]
}
```

---

### Phase B: Leaf Node Analysis (Manual)

**Goal**: Deeply understand all leaf functions

**Selection Criteria**:
- Functions with `depth == 0` (true leaves)
- Functions calling only library functions (pseudo-leaves)

**Analysis Process per Leaf**:
1. Extract disassembly
2. Identify register usage
3. Reverse-engineer to C
4. Document data structures
5. Classify purpose
6. Create Markdown doc

**Estimated Leaves**: ~20-30 functions

**Time per Leaf**: 15-30 minutes (simple) to 1 hour (complex)

**Total Time**: 1-2 days for all leaves

---

### Phase C: Layer 1 Functions

**Goal**: Analyze functions that call only leaves

**Example**:
```
Layer 1: FUN_00003284
  └─> calls: FUN_00003820 (analyzed ✓)
  └─> calls: library functions (known ✓)
```

**Benefits**:
- All callees already understood
- Can focus on this function's unique logic
- Data flow from leaves is clear

**Time per Function**: 30 minutes - 1 hour

---

### Phase D: Layer 2+ Functions

**Goal**: Work up the tree, one layer at a time

**Process**:
1. Analyze all Layer N functions
2. Move to Layer N+1
3. Repeat until root reached

**Root Functions**:
- Entry point (0x00002D10)
- ND_GetBoardList (0x00002DC6)
- Main initialization functions

---

## Concrete Implementation

### Step 1: Build Call Graph with Depth

```python
# analyze_call_graph.py
import json

# Load Ghidra call graph
with open('ghidra_export/call_graph.json') as f:
    call_graph = json.load(f)

# Build reverse index (who calls this function)
called_by = {}
for entry in call_graph:
    func_addr = entry['function']['address']
    for callee in entry['calls']:
        callee_addr = callee['address']
        if callee_addr not in called_by:
            called_by[callee_addr] = []
        called_by[callee_addr].append(func_addr)

# Calculate depth (leaf = 0, parent of leaf = 1, etc.)
def calculate_depth(addr, memo={}):
    if addr in memo:
        return memo[addr]

    # Find this function's calls
    calls = []
    for entry in call_graph:
        if entry['function']['address'] == addr:
            calls = entry['calls']
            break

    # If no calls, it's a leaf (depth 0)
    if not calls:
        memo[addr] = 0
        return 0

    # Depth = 1 + max(callee depths)
    max_depth = 0
    for callee in calls:
        callee_addr = callee['address']
        callee_depth = calculate_depth(callee_addr, memo)
        max_depth = max(max_depth, callee_depth)

    memo[addr] = max_depth + 1
    return max_depth + 1

# Output analysis order
leaves = []
for entry in call_graph:
    addr = entry['function']['address']
    depth = calculate_depth(addr)
    entry['depth'] = depth
    entry['called_by'] = called_by.get(addr, [])

    if depth == 0:
        leaves.append(entry)

print(f"Identified {len(leaves)} leaf functions")
print("Analysis order:")
for leaf in sorted(leaves, key=lambda x: x['function']['address']):
    print(f"  {leaf['function']['address_hex']}: {leaf['function']['name']}")
```

---

### Step 2: Prioritize Leaf Analysis

**Critical Leaves** (protocol-relevant):
1. Functions accessing hardware registers (grep for 0x02000000, 0xF8000000)
2. Functions with NeXTdimension-related strings
3. Functions called by ND_GetBoardList

**Utility Leaves** (lower priority):
1. String manipulation helpers
2. Math helpers
3. Generic memory operations

**Analysis Order**:
```
Priority 1: Critical leaves (hardware/protocol)
Priority 2: Leaves called by ND_GetBoardList
Priority 3: Other leaves (utilities)
```

---

### Step 3: Document Each Layer

**Layer 0 (Leaves)**:
```
docs/functions/
  ├── layer0_leaves/
  │   ├── 00003820_ND_LookupBoardBySlot.md
  │   ├── 00004xxx_helper1.md
  │   └── ...
```

**Layer 1**:
```
docs/functions/
  ├── layer1/
  │   ├── 00003284_function.md
  │   └── ...
```

**Benefits**:
- Easy to see analysis progress
- Can reference "all leaves are done" when working on Layer 1
- Clear dependencies

---

## Call Graph Layering Example

```
Layer 3: Entry Point (0x00002D10)
  │
  ├─> Layer 2: ND_GetBoardList (0x00002DC6)
  │     │
  │     ├─> Layer 1: FUN_00003284
  │     │     │
  │     │     └─> Layer 0: FUN_00003820 (ND_LookupBoardBySlot) ✓ DONE
  │     │
  │     ├─> Layer 0: printf (library)
  │     ├─> Layer 0: malloc (library)
  │     └─> Layer 0: port_allocate (library)
  │
  └─> Layer 1: Other functions
        └─> Layer 0: Utility leaves
```

**Analysis Flow**:
1. ✅ Analyze Layer 0: FUN_00003820 (done - 30 min)
2. Analyze remaining Layer 0 leaves (1-2 days)
3. Analyze Layer 1: FUN_00003284 (now easy - callees known)
4. Analyze Layer 2: ND_GetBoardList (now tractable - all subcalls understood)
5. Analyze Layer 3: Entry point (straightforward - just orchestration)

---

## Benefits Realized

### Time Savings

**Top-Down** (traditional):
- Spend 3 hours on ND_GetBoardList, still confused
- Realize need to understand FUN_00003820
- Analyze FUN_00003820 (30 min)
- Re-analyze ND_GetBoardList with new knowledge (2 hours)
- **Total**: 5.5 hours, lots of rework

**Bottom-Up** (our approach):
- Analyze FUN_00003820 (30 min)
- Analyze ND_GetBoardList with full context (1.5 hours)
- **Total**: 2 hours, no rework

**Savings**: 63% faster ✅

---

### Quality Improvements

**Accuracy**:
- No guessing about what callees do
- Fewer errors in C pseudocode
- Correct data structure definitions

**Completeness**:
- All functions understood at same depth
- No "TBD" comments on callees
- Full dependency knowledge

**Maintainability**:
- Easy to update when new info found
- Changes propagate up naturally
- Clear "done" criteria per layer

---

## Implementation Timeline

**Week 1**:
- Day 1-2: Build call graph with depth, identify leaves
- Day 3-5: Analyze all Layer 0 leaves (~20-30 functions)

**Week 2**:
- Day 1-3: Analyze Layer 1 functions
- Day 4-5: Analyze Layer 2 functions

**Week 3**:
- Day 1-2: Analyze Layer 3+ (roots)
- Day 3-5: Protocol synthesis (combine all knowledge)

**Week 4**:
- Polish, annotate, document

---

## Decision: Bottom-Up Confirmed ✅

**Strategy**: Leaf nodes first, work up the call graph

**Next Actions**:
1. Create `analyze_call_graph.py` script
2. Identify all leaf functions
3. Prioritize critical leaves
4. Begin systematic Layer 0 analysis
5. Create function docs as we go
6. Move up one layer at a time

This approach guarantees:
- ✅ Maximum efficiency (no rework)
- ✅ Highest accuracy (full context)
- ✅ Clear progress tracking (by layer)
- ✅ Natural data structure discovery
- ✅ Protocol understanding emerges organically
