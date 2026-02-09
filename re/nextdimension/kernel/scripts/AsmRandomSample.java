// Assembly-level random function sampler for i860 firmware analysis.
//
// Outputs per-function instruction listings plus lightweight metrics:
// call/jump counts, return patterns, memory-op density, and out-of-range flows.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.FlowType;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Random;

public class AsmRandomSample extends GhidraScript {

    private static class Metrics {
        int insnCount;
        int callCount;
        int branchCount;
        int returnCount;
        int memoryOpCount;
        int outOfRangeFlows;
        boolean prologueStackAlloc;
        boolean prologueRetSave;
        long sizeBytes;
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();

        int sampleCount = Integer.getInteger("ghidra.asm.sample.count", 12);
        int minBytes = Integer.getInteger("ghidra.asm.sample.min_bytes", 24);
        int maxInsns = Integer.getInteger("ghidra.asm.sample.max_insns", 40);
        long seed = Long.getLong("ghidra.asm.sample.seed", System.currentTimeMillis());

        List<Function> candidates = collectCandidates(listing, minBytes);
        Random rng = new Random(seed);
        Collections.shuffle(candidates, rng);

        int selected = Math.min(sampleCount, candidates.size());
        List<Function> sample = new ArrayList<>(candidates.subList(0, selected));
        sample.sort(Comparator.comparingLong(f -> f.getEntryPoint().getOffset()));

        StringBuilder sb = new StringBuilder();
        sb.append("=== i860 Random Assembly Function Sample ===\n\n");
        sb.append(String.format("Program: %s\n", currentProgram.getName()));
        sb.append(String.format("Language: %s\n", currentProgram.getLanguageID()));
        sb.append(String.format("Compiler: %s\n", currentProgram.getCompilerSpec().getCompilerSpecID()));
        sb.append(String.format("Seed: %d\n", seed));
        sb.append(String.format("Candidates: %d (min bytes=%d)\n", candidates.size(), minBytes));
        sb.append(String.format("Selected: %d (requested %d, max insns/function=%d)\n\n",
            selected, sampleCount, maxInsns));

        int totalInsns = 0;
        int totalCalls = 0;
        int totalBranches = 0;
        int totalReturns = 0;
        int totalMemOps = 0;
        int totalOutOfRange = 0;
        int withStackAlloc = 0;
        int withRetSave = 0;
        int withOutOfRange = 0;

        for (Function f : sample) {
            if (monitor.isCancelled()) break;
            Metrics m = analyzeFunction(listing, memory, f, maxInsns, sb);

            totalInsns += m.insnCount;
            totalCalls += m.callCount;
            totalBranches += m.branchCount;
            totalReturns += m.returnCount;
            totalMemOps += m.memoryOpCount;
            totalOutOfRange += m.outOfRangeFlows;
            if (m.prologueStackAlloc) withStackAlloc++;
            if (m.prologueRetSave) withRetSave++;
            if (m.outOfRangeFlows > 0) withOutOfRange++;
        }

        sb.append("════════════════════════════════════════════════════════════════\n");
        sb.append("Sample Summary\n");
        sb.append(String.format("  instructions: %d\n", totalInsns));
        sb.append(String.format("  calls: %d\n", totalCalls));
        sb.append(String.format("  branches/jumps: %d\n", totalBranches));
        sb.append(String.format("  returns: %d\n", totalReturns));
        sb.append(String.format("  memory ops: %d\n", totalMemOps));
        sb.append(String.format("  out-of-range flows: %d (functions affected: %d/%d)\n",
            totalOutOfRange, withOutOfRange, selected));
        sb.append(String.format("  prologue stack alloc detected: %d/%d\n", withStackAlloc, selected));
        sb.append(String.format("  prologue return-save detected: %d/%d\n", withRetSave, selected));
        sb.append("════════════════════════════════════════════════════════════════\n");

        String out = sb.toString();
        printf("%s", out);

        String outPath = System.getProperty(
            "ghidra.asm.sample.output",
            "/tmp/i860_kernel_asm_random.txt"
        );
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        pw.print(out);
        pw.close();
        printf("\nWritten to: %s\n", outPath);
    }

    private List<Function> collectCandidates(Listing listing, int minBytes) {
        List<Function> out = new ArrayList<>();
        FunctionIterator it = listing.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f == null) continue;
            String name = f.getName();
            if (name != null && name.startsWith("data_")) continue;
            if (f.getBody().getNumAddresses() < minBytes) continue;
            if (listing.getInstructionAt(f.getEntryPoint()) == null) continue;
            out.add(f);
        }
        return out;
    }

    private Metrics analyzeFunction(
        Listing listing,
        Memory memory,
        Function f,
        int maxInsns,
        StringBuilder sb
    ) {
        Metrics m = new Metrics();
        m.sizeBytes = f.getBody().getNumAddresses();

        sb.append("════════════════════════════════════════════════════════════════\n");
        sb.append(String.format("  %s (%d bytes)\n", f.getName(), m.sizeBytes));
        sb.append(String.format("  @ %s\n", f.getEntryPoint()));
        sb.append("════════════════════════════════════════════════════════════════\n");
        sb.append("  address     word      instruction\n");
        sb.append("  ----------  --------  ---------------------------------------\n");

        InstructionIterator ii = listing.getInstructions(f.getBody(), true);
        int shown = 0;
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            m.insnCount++;

            FlowType ft = insn.getFlowType();
            if (ft != null) {
                if (ft.isCall()) m.callCount++;
                if (ft.isJump() || ft.isTerminal()) m.branchCount++;
            }

            String mn = insn.getMnemonicString().toLowerCase(Locale.ROOT);
            if (isMemoryMnemonic(mn)) m.memoryOpCount++;
            if (isReturnInstruction(memory, insn)) m.returnCount++;

            for (Address target : insn.getFlows()) {
                if (target == null) continue;
                if (!memory.contains(target)) m.outOfRangeFlows++;
            }

            if (m.insnCount <= 6) {
                Integer word = readWord(memory, insn.getAddress());
                if (word != null) {
                    if (isStackAllocWord(word.intValue())) m.prologueStackAlloc = true;
                    if (isRetSaveWord(word.intValue())) m.prologueRetSave = true;
                }
            }

            if (shown < maxInsns) {
                Integer word = readWord(memory, insn.getAddress());
                String wordHex = word != null ? String.format("%08X", word.intValue()) : "????????";
                sb.append(String.format("  %08X  %s  %s\n",
                    insn.getAddress().getOffset(), wordHex, insn.toString()));
                shown++;
            }
        }

        if (m.insnCount > maxInsns) {
            sb.append(String.format("  ... (%d more instructions)\n", m.insnCount - maxInsns));
        }

        sb.append(String.format(
            "  metrics: insns=%d calls=%d branches=%d returns=%d memops=%d out_of_range_flows=%d prologue(stack_alloc=%s,ret_save=%s)\n\n",
            m.insnCount,
            m.callCount,
            m.branchCount,
            m.returnCount,
            m.memoryOpCount,
            m.outOfRangeFlows,
            m.prologueStackAlloc ? "yes" : "no",
            m.prologueRetSave ? "yes" : "no"
        ));
        return m;
    }

    private Integer readWord(Memory memory, Address addr) {
        try {
            return Integer.valueOf(memory.getInt(addr));
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isMemoryMnemonic(String m) {
        return m.startsWith("ld") || m.startsWith("st") ||
               m.startsWith("fld") || m.startsWith("fst") ||
               m.startsWith("pfld") || m.startsWith("pfst");
    }

    private static boolean isReturnInstruction(Memory memory, Instruction insn) {
        String mnemonic = insn.getMnemonicString();
        if ("ret".equals(mnemonic) || "_ret".equals(mnemonic)) return true;
        if (!"bri".equals(mnemonic) && !"_bri".equals(mnemonic)) return false;
        try {
            int word = memory.getInt(insn.getAddress());
            int op6 = (word >>> 26) & 0x3F;
            int src1 = (word >>> 11) & 0x1F;
            return op6 == 0x10 && src1 == 1;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isStackAllocWord(int word) {
        int op6 = (word >>> 26) & 0x3F;
        int src2 = (word >>> 21) & 0x1F;
        int dest = (word >>> 16) & 0x1F;
        short simm16 = (short)(word & 0xFFFF);
        if (op6 != 0x21) return false; // addu imm16,src2,dest
        if (simm16 >= 0 || simm16 < -4096) return false;
        return (src2 == 2 && dest == 2) || (src2 == 29 && dest == 29);
    }

    private static boolean isRetSaveWord(int word) {
        int op6 = (word >>> 26) & 0x3F;
        int src2 = (word >>> 21) & 0x1F;
        int dest = (word >>> 16) & 0x1F;
        short simm16 = (short)(word & 0xFFFF);
        return op6 == 0x27 && src2 == 1 && dest != 0 && simm16 == 0; // subs 0,r1,rN
    }
}
