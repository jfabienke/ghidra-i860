// Print analysis statistics for an imported program.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class AnalysisStats extends GhidraScript {

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();

        int functions = 0;
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) {
            fi.next();
            functions++;
        }

        int instructions = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            ii.next();
            instructions++;
        }

        int dataItems = 0;
        DataIterator di = listing.getDefinedData(true);
        while (di.hasNext()) {
            di.next();
            dataItems++;
        }

        long codeBytes = 0;
        long totalBytes = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            long size = block.getSize();
            totalBytes += size;
            if (block.isExecute()) {
                codeBytes += size;
            }
        }

        printf("=== Analysis Stats: %s ===%n", currentProgram.getName());
        printf("Language:     %s%n", currentProgram.getLanguageID());
        printf("Compiler:     %s%n", currentProgram.getCompilerSpec().getCompilerSpecID());
        printf("Memory:       %d bytes total, %d bytes executable%n", totalBytes, codeBytes);
        printf("Functions:    %d%n", functions);
        printf("Instructions: %d%n", instructions);
        printf("Data items:   %d%n", dataItems);

        // List memory blocks
        printf("%n--- Memory Blocks ---%n");
        for (MemoryBlock block : memory.getBlocks()) {
            printf("  %-20s %08x-%08x  %6d bytes  %s%s%s%n",
                block.getName(),
                block.getStart().getOffset(),
                block.getEnd().getOffset(),
                block.getSize(),
                block.isRead() ? "r" : "-",
                block.isWrite() ? "w" : "-",
                block.isExecute() ? "x" : "-");
        }
    }
}
