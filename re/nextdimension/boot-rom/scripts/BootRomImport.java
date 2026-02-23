// Import boot ROM with known entry points for recursive descent.
// Seeds function starts from ROM disassembly analysis, then lets
// Ghidra auto-analysis create functions and follow control flow.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class BootRomImport extends GhidraScript {

    // Known entry points from ND_ROM_STRUCTURE.md disassembly analysis
    private static final long[] ENTRY_POINTS = {
        0xFFF00020L,  // Boot entry (exception vector 6, execution start)
        0xFFF0037CL,  // Memory init subroutine (called 3x with DRAM bank addrs)
        0xFFF00540L,  // Core init routines (memory detection, VRAM config)
        0xFFF0079CL,  // Hardware detection call target
        0xFFF009C0L,  // Hardware detection (RAM sizing, HW ID, status polling)
        0xFFF00B2CL,  // Subroutine called from main loop
        0xFFF00B78L,  // Subroutine called from main loop
        0xFFF00BE0L,  // Device init (RAMDAC 28-loop, graphics controller)
        0xFFF01580L,  // Main runtime (mailbox polling, kernel loader) - largest
        0xFFF01618L,  // Subroutine (memory test with 0xAAAA pattern)
        0xFFF017F4L,  // Subroutine called from main loop
        0xFFF019D0L,  // Subroutine called from main loop
        0xFFF01A98L,  // Subroutine called from main loop
        0xFFF01B04L,  // Subroutine called from main loop
        0xFFF02560L,  // Service routines (memcpy, memset, memcmp)
        0xFFF02590L,  // Service routine
    };

    @Override
    public void run() throws Exception {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Clear all existing data so disassembly can proceed (BinaryLoader creates bytes)
        currentProgram.getListing().clearAll(false, monitor);

        int seeded = 0;
        int disassembled = 0;

        for (long entry : ENTRY_POINTS) {
            Address addr = space.getAddress(entry);
            try {
                disassemble(addr);
                Instruction insn = getInstructionAt(addr);
                if (insn != null) {
                    disassembled++;
                    // Create function at this address
                    createFunction(addr, null);
                    seeded++;
                }
            } catch (Exception e) {
                printerr("Failed to seed " + addr + ": " + e.getMessage());
            }
        }

        // Also seed the reset vector
        Address resetVector = space.getAddress(0xFFF1FF20L);
        try {
            disassemble(resetVector);
        } catch (Exception e) {
            // ok if this fails
        }

        printf("Boot ROM import: %d entry points seeded, %d disassembled%n",
               seeded, disassembled);
    }
}
