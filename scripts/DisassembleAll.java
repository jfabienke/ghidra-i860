// Linear sweep disassembly for raw binary imports.
// BinaryLoader creates byte data that blocks disassembly, so we clear
// all existing data and disassemble at every 4-byte aligned address.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DisassembleAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long minAddr = currentProgram.getMinAddress().getOffset();
        long maxAddr = currentProgram.getMaxAddress().getOffset();

        // Clear all existing data/code so disassembly can proceed
        currentProgram.getListing().clearAll(false, monitor);

        int decoded = 0;
        int failed = 0;

        // Export disassembly to file for comparison
        String exportPath = System.getProperty("ghidra.export.path", "/tmp/ghidra_disasm.txt");
        PrintWriter pw = new PrintWriter(new FileWriter(exportPath));

        for (long offset = minAddr; offset <= maxAddr - 3; offset += 4) {
            Address addr = space.getAddress(offset);
            try {
                disassemble(addr);
                Instruction insn = getInstructionAt(addr);
                if (insn != null) {
                    decoded++;
                    pw.printf("0x%08x: %s%n", offset, insn.toString());
                } else {
                    failed++;
                    pw.printf("0x%08x: <failed>%n", offset);
                }
            } catch (Exception e) {
                failed++;
                pw.printf("0x%08x: <error>%n", offset);
            }
        }

        pw.close();
        printf("Disassembly complete: %d decoded, %d failed out of %d total%n",
               decoded, failed, decoded + failed);
        printf("Exported to: %s%n", exportPath);
    }
}
