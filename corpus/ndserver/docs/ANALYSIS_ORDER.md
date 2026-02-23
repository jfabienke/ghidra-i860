# Analysis Order - Bottom-Up Strategy

**Generated**: Automatic from call graph analysis
**Strategy**: Leaf nodes first, work up the call graph

---

## Layer Statistics

| Layer | Count | Description |
|-------|-------|-------------|
| 0 | 21 | Leaf functions (no internal calls) |
| 1 | 4 | Calls Layer 0-0 functions |
| 2 | 3 | Calls Layer 0-1 functions |
| 3 | 1 | Calls Layer 0-2 functions |

**Total**: 29 functions

---

## Analysis Plan

### Phase 1: Layer 0 (Leaf Functions)

**Count**: 21 functions
**Time Estimate**: 15-30 min each = 5-10 hours total

#### Priority 1: Critical Leaves (2)

These are called by multiple functions or have significant library usage:

1. `0x000036b2` - **FUN_000036b2** (called by 3, lib calls: 0)
2. `0x0000709c` - **FUN_0000709c** (called by 3, lib calls: 0)


#### Priority 2: Utility Leaves (19)

Simpler helper functions, analyze after critical leaves.


### Phase 2: Layer 1

**Count**: 4 functions
**Prerequisite**: All Layer 0-0 functions analyzed

- `0x0000399c` - **FUN_0000399c** (calls 5 internal functions)
- `0x00006f94` - **FUN_00006f94** (calls 1 internal functions)
- `0x00007032` - **FUN_00007032** (calls 1 internal functions)
- `0x00007072` - **FUN_00007072** (calls 1 internal functions)

### Phase 3: Layer 2

**Count**: 3 functions
**Prerequisite**: All Layer 0-1 functions analyzed

- `0x00005a3e` - **FUN_00005a3e** (calls 5 internal functions)
- `0x00005af6` - **FUN_00005af6** (calls 5 internal functions)
- `0x00005bb8` - **FUN_00005bb8** (calls 5 internal functions)

### Phase 4: Layer 3

**Count**: 1 functions
**Prerequisite**: All Layer 0-2 functions analyzed

- `0x00002dc6` - **FUN_00002dc6** (calls 12 internal functions)
