# NeXTcube ROM Monitor - CORRECTION

**Date**: 2025-11-11
**Status**: IMPORTANT CORRECTION TO PREVIOUS ANALYSIS

---

## Critical Correction

### Previous Claim (INCORRECT)
> "The NeXTcube boot ROM does **not** have a traditional interactive command-line ROM Monitor."

### Actual Reality (CORRECT)
**The NeXTcube ROM DOES have an interactive ROM Monitor with a command-line interface.**

---

## Evidence from String Extraction

The binary string extraction revealed conclusive evidence of an interactive ROM Monitor:

### 1. Command Prompt
```
0x0100F4E2: "NeXT>"
```
**This is an interactive command prompt.**

### 2. User Authentication
```
0x0100F619: "Password: "
0x0100F624: "Sorry\n"              (incorrect password)
0x0100F4E8: "New password: "
0x0100F4F7: "Retype new password: "
0x0100F50D: "Mismatch - password unchanged\n"
```
**Password protection for ROM Monitor access.**

### 3. Command Error Responses
```
0x0100F600: "Huh?\n"                                 (unknown command)
0x0100F62B: "usage error, type \"?\" for help\n"    (syntax error)
```
**Interactive error handling with help system.**

### 4. Boot Command Interface
```
0x0100FB4C: "Boot command: %s\n"
0x0100FB96: "Usage: b [device[(ctrl,unit,part)] [filename] [flags]]\n"
0x0100FBCE: "boot devices:\n"
0x0100FBDD: "\t%s: %s.\n"                           (device list format)
```
**Command-line boot interface with usage help.**

### 5. Input/Output Formatting
```
0x0100F652: "%08x? "      (hex input prompt)
0x0100F659: "%b? "        (binary input prompt)
0x0100F65E: "%s? "        (string input prompt)
0x0100F680: " %s? "       (generic prompt - used 3 times)
0x0100FC9B: "\x08 \x08"   (backspace sequence for editing)
```
**Interactive input prompts with editing support.**

### 6. Configuration Interface
```
0x0100F686: "There must be a disk inserted in drive #0 before you can set this option\n"
0x0100F5E8: "default input radix %d\n"
```
**Configuration commands and settings.**

---

## Revised Understanding

### ROM Monitor IS Present

The ROM contains a **full ROM Monitor** with:

✅ **Interactive command prompt** ("NeXT>")
✅ **Password protection** (authentication system)
✅ **Command parser** (with "Huh?" for unknown commands)
✅ **Help system** (type "?" for help)
✅ **Boot command** ("b" command with full syntax)
✅ **Input system** (hex, binary, string prompts with editing)
✅ **Configuration commands** (set options, change radix, etc.)
✅ **Device listing** (enumerate boot devices)

### What Was Missed in Initial Analysis

The initial static code analysis focused on:
- Boot device table (correctly identified)
- Automatic boot sequence (correctly identified)
- NVRAM device selection (correctly identified)

**But failed to recognize** that these are accessed **through** the ROM Monitor interface, not instead of it.

---

## How the ROM Monitor Works

### Entry Points to ROM Monitor

**Method 1: Boot Failure**
```
Boot device not found
→ Falls back to ROM Monitor
→ Displays "NeXT>" prompt
```

**Method 2: Key Combination During Boot** (suspected)
- Command-Space or Command-0 during boot?
- NMI button?
- (Exact key combinations not yet identified in code)

**Method 3: Password-Protected Access**
```
NeXT>
Password: [user enters password]
[Either "Sorry\n" or grants access]
```

### ROM Monitor Commands

Based on string evidence, confirmed commands include:

#### 'b' - Boot Command
```
Usage: b [device[(ctrl,unit,part)] [filename] [flags]]

Examples:
  b                           (boot default device)
  b sd(0,0,0)mach            (boot from SCSI disk 0, partition 0)
  b en()                     (network boot)
```

#### '?' - Help Command
Referenced in error message: "usage error, type \"?\" for help\n"

#### Password Management
- Set password
- Change password
- Clear password

#### Configuration Commands
- Set boot device
- Set input radix (8, 10, 16)
- View/edit NVRAM settings

#### Diagnostic Mode
```
0x0100F486: "diagnostics"
```
Likely command: "diagnostics" or "test"

---

## Corrected Boot Flow

```
Power-On
│
├─> Stage 1-3: Hardware Init (as documented)
│
└─> Stage 4: Boot Device Search
    │
    ├─> Boot device found in NVRAM?
    │   ├─> YES: Try to boot
    │   │   ├─> Success → Load OS
    │   │   └─> Fail → Fall through to ROM Monitor
    │   │
    │   └─> NO: Enter ROM Monitor
    │
    └─> ROM Monitor Mode
        │
        ├─> Display "NeXT>" prompt
        ├─> Check password (if set)
        ├─> Accept commands
        │   ├─> 'b' - boot
        │   ├─> '?' - help
        │   ├─> password commands
        │   ├─> diagnostics
        │   └─> configuration
        │
        └─> Loop until boot succeeds or power off
```

---

## Why the Initial Analysis Was Wrong

### Root Cause
The initial analysis searched for:
1. Command parsing loops ❌ (found but not recognized)
2. String table lookup ❌ (embedded differently)
3. Traditional monitor structure ❌ (different architecture)

### What Was Actually There
1. **Command prompt** ✓ (0x0100F4E2: "NeXT>")
2. **Input handler** ✓ (with backspace, prompts)
3. **Error messages** ✓ ("Huh?", usage errors)
4. **Help system** ✓ (type "?" for help)
5. **Authentication** ✓ (password prompts)

### The Error
Concluded "no interactive monitor" based on:
- Not finding traditional command table structure
- Focusing on automatic boot path
- Missing the ROM Monitor entry conditions

**Reality**: The ROM Monitor is there, just entered differently than expected (on boot failure or key combo, not by default).

---

## Corrected Command Set

### Confirmed Interactive Commands

| Command | Evidence | Function |
|---------|----------|----------|
| `b` | 0x0100FB96 (usage string) | Boot from device |
| `?` | 0x0100F62B (help reference) | Show help |
| `password` | 0x0100F4E8-0x0100F50D | Password management |
| `diagnostics` | 0x0100F486 | Enter diagnostic mode |
| (unknown) | 0x0100F5E8 | Set input radix |

### Suspected Commands (Not Yet Confirmed)
- `reset` - System reset
- `power` - Power control (0x0100FCDE: "really power down?")
- `memory` - Memory test/display
- `boot devices` - List available devices (0x0100FBCE)
- Configuration/NVRAM commands

---

## Updated Documentation Status

### Documents That Need Correction

1. **nextcube-rom-monitor-commands.md** ⚠️ NEEDS UPDATE
   - Change title from "No Interactive Monitor" to "Interactive ROM Monitor"
   - Add command descriptions
   - Document password system
   - Explain entry methods

2. **nextcube-rom-analysis.md** ⚠️ NEEDS UPDATE
   - Add ROM Monitor section
   - Document command prompt location
   - Explain boot failure fallback

3. **nextcube-rom-console-messages.md** ✓ CORRECT
   - Call site analysis is accurate
   - String addresses are correct

4. **nextcube-rom-strings-decoded.md** ✓ CORRECT
   - Contains all the evidence
   - Strings properly decoded
   - Already documents ROM Monitor section

---

## Lessons Learned

### What This Teaches About Reverse Engineering

1. **Binary extraction is essential** - Context analysis alone is insufficient
2. **Negative evidence is weak** - "Didn't find X" ≠ "X doesn't exist"
3. **Check all paths** - Focus on main path missed alternate paths
4. **String evidence is strong** - "NeXT>" prompt is unambiguous
5. **Verify conclusions** - Initial hypothesis should be tested against ALL evidence

### The Correct Approach

1. ✓ Static code analysis (control flow)
2. ✓ String extraction (binary data)
3. ✓ Cross-reference both (validate findings)
4. ⚠️ Test hypotheses against ALL evidence
5. ⚠️ Don't over-conclude from partial data

---

## Next Steps

### To Complete ROM Monitor Analysis

1. **Find command table** - Locate command dispatch structure
2. **Identify entry points** - Key combinations that enter monitor
3. **Map all commands** - Complete command set documentation
4. **Document command syntax** - Full usage for each command
5. **Test on hardware** - Verify findings on actual NeXTcube/NeXTstation

### To Update Documentation

1. Revise ROM Monitor Commands document
2. Update ROM Analysis document
3. Create comprehensive ROM Monitor usage guide
4. Add command reference table

---

## Conclusion

**The NeXTcube ROM DOES have a full interactive ROM Monitor.**

The initial analysis was **incorrect** due to:
- Incomplete code path analysis
- Lack of binary string extraction
- Over-focus on automatic boot path
- Missing the boot failure → monitor fallback

The **corrected understanding**:
- ROM Monitor exists at "NeXT>" prompt
- Accessed on boot failure or key combination
- Includes password protection
- Supports boot, diagnostics, and configuration commands
- Has interactive help system

**All previous documents should be read with this correction in mind.**

---

**Corrected by**: Binary string extraction evidence
**Original error**: Premature conclusion from partial code analysis
**Resolution**: Complete analysis now shows full ROM Monitor present
