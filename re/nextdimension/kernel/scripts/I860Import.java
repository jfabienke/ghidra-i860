// Pre-analysis script for i860 Mach-O binaries.
// Ghidra's Mach-O loader can't parse the i860 thread command (flavor 0x4),
// so we set the entry point manually and disassemble via recursive descent.
//
// After the initial descent from entry, we scan raw bytes for call/branch
// targets (opcodes 0x1A-0x1F), detect and exclude embedded non-i860 Mach-O
// objects, and iteratively follow decoded flows until convergence. This
// bootstraps substantially more code before auto-analysis runs.
//
// Run as -preScript so auto-analysis can build on the results.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.regex.*;

public class I860Import extends GhidraScript {

    private Listing listing;
    private Memory memory;
    private AddressSpace space;
    private AddressSet execSet;
    private AddressSet analysisSet;
    private List<long[]> execRanges;
    private List<long[]> embeddedObjects;
    private String seedMapPath = null;
    private List<AddressRange> allowRanges = new ArrayList<>();
    private List<AddressRange> denyRanges = new ArrayList<>();

    static class AddressRange {
        final long start;
        final long end;
        final String label;

        AddressRange(long start, long end, String label) {
            if (start <= end) {
                this.start = start;
                this.end = end;
            } else {
                this.start = end;
                this.end = start;
            }
            this.label = label;
        }
    }

    @Override
    public void run() throws Exception {
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        parseScriptArgs(getScriptArgs());

        printf("=== I860Import preScript (recursive descent) ===%n");

        // --- Phase 1: Set entry point at first executable block ---
        Address entry = null;
        execSet = new AddressSet();
        execRanges = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute()) {
                execSet.add(block.getStart(), block.getEnd());
                execRanges.add(new long[]{block.getStart().getOffset(), block.getEnd().getOffset()});
                if (entry == null) entry = block.getStart();
            }
        }
        if (entry == null) {
            printerr("No executable memory block found");
            return;
        }

        // --- Phase 2: Detect embedded non-i860 objects ---
        embeddedObjects = detectEmbeddedObjects();
        loadSeedMap();
        buildAnalysisSet();

        if (analysisSet.isEmpty()) {
            printerr("Analysis set is empty after applying executable/object/map filters");
            return;
        }

        if (!isCandidateTargetAddress(entry.getOffset())) {
            Address fallback = analysisSet.getMinAddress();
            if (fallback == null) {
                printerr("No valid candidate entry point after filtering");
                return;
            }
            printf("Entry point %s excluded by filters; using %s%n", entry, fallback);
            entry = fallback;
        }

        printf("Entry point: %s%n", entry);
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        currentProgram.getSymbolTable().createLabel(entry, "entry", SourceType.USER_DEFINED);

        printf("Embedded non-i860 objects: %d%n", embeddedObjects.size());
        for (long[] obj : embeddedObjects) {
            printf("  %08X - %08X (%,d bytes)%n", obj[0], obj[1], obj[1] - obj[0]);
        }
        if (seedMapPath != null) {
            printf("Recovery map: %s (allow=%d, deny=%d)%n",
                seedMapPath, allowRanges.size(), denyRanges.size());
        }
        printf("Analysis set ranges: %d%n", analysisSet.getNumAddressRanges());

        // --- Phase 3: Initial recursive descent from entry ---
        DisassembleCommand cmd = new DisassembleCommand(entry, analysisSet, true);
        cmd.applyTo(currentProgram);

        int decoded = countInstructions();
        printf("Initial descent from entry: %d instructions%n", decoded);

        // --- Phase 4: Iterative seed discovery ---
        // Scan raw bytes for call/br targets, then follow decoded flows.
        int round = 0;
        int totalCallBrSeeds = 0;
        int totalFlowSeeds = 0;

        while (round < 30) {
            round++;
            if (monitor.isCancelled()) break;
            int before = countInstructions();

            // A: Scan raw bytes for call/branch targets (0x1A-0x1F)
            int callBrSeeds = seedFromCallBrTargets();
            totalCallBrSeeds += callBrSeeds;

            // B: Follow decoded instruction flow targets
            int flowSeeds = seedFromDecodedFlows();
            totalFlowSeeds += flowSeeds;

            int after = countInstructions();
            int delta = after - before;

            printf("  Round %d: +%d insns (call/br=%d, flow=%d)%n",
                   round, delta, callBrSeeds, flowSeeds);

            if (delta == 0) break;
            decoded = after;
        }

        printf("Recursive descent complete: %d instructions in %d rounds%n", decoded, round);
        printf("  Call/br seeds: %d, Flow seeds: %d%n", totalCallBrSeeds, totalFlowSeeds);

        // --- Phase 5: Fix orphan delay slots ---
        // Instructions with delay slots (call, br, bc.t, bnc.t, bla, calli, bri)
        // reference PC+4 for the delay slot. If that instruction isn't decoded
        // (edge of a code island), we get pcode errors. Force-decode those.
        int delayFixed = fixOrphanDelaySlots();
        if (delayFixed > 0) {
            printf("Fixed %d orphan delay slot instructions%n", delayFixed);
        }

        decoded = countInstructions();
        printf("Final instruction count: %d%n", decoded);

        // --- Phase 6: Create entry function ---
        createFunction(entry, "entry");
    }

    // Scan raw bytes of executable blocks for 26-bit branch/call instructions.
    // Opcodes 0x1A-0x1F: br, call, bc, bc.t, bnc, bnc.t
    // Target = PC + (sign_extend(bits[25:0]) << 2)
    private int seedFromCallBrTargets() throws Exception {
        int seeded = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            long blockSize = endOff - startOff + 1;

            byte[] bytes = new byte[(int)blockSize];
            block.getBytes(block.getStart(), bytes);

            for (int i = 0; i < bytes.length - 3; i += 4) {
                if (monitor.isCancelled()) break;

                long srcAddr = startOff + i;
                if (!isCandidateAddress(srcAddr)) continue;

                int word = readWordLE(bytes, i);
                int op6 = (word >>> 26) & 0x3F;
                if (op6 < 0x1A || op6 > 0x1F) continue;

                int offset26 = word & 0x03FFFFFF;
                if ((offset26 & 0x02000000) != 0) {
                    offset26 |= 0xFC000000;
                }

                long target = srcAddr + ((long)offset26 << 2);

                if (!isCandidateTargetAddress(target)) continue;

                Address targetAddr = space.getAddress(target);
                if (listing.getInstructionAt(targetAddr) != null) continue;

                DisassembleCommand cmd = new DisassembleCommand(targetAddr, analysisSet, true);
                cmd.applyTo(currentProgram);
                if (listing.getInstructionAt(targetAddr) != null) {
                    seeded++;
                    // Create function at call targets (0x1B) — definite function entries
                    if (op6 == 0x1B) {
                        try { createFunction(targetAddr, null); } catch (Exception e) {}
                    }
                }
            }
        }
        return seeded;
    }

    // Fix delay slot instructions where PC+4 (the delay slot) isn't decoded.
    // These cause "Program does not contain referenced instruction" pcode errors.
    // Delay-slot opcodes (raw decode):
    //   br(0x1A), call(0x1B), bc.t(0x1D), bnc.t(0x1F),
    //   bla(0x2D), bri/ret(0x10), calli(0x13 escop=2)
    private int fixOrphanDelaySlots() {
        int fixed = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            try {
                int word = memory.getInt(insn.getAddress());
                if (!hasDelaySlot(word)) continue;

                Address nextAddr = insn.getAddress().add(4);
                if (!analysisSet.contains(nextAddr)) continue;
                if (!isCandidateAddress(nextAddr.getOffset())) continue;
                if (listing.getInstructionAt(nextAddr) != null) continue;

                DisassembleCommand cmd = new DisassembleCommand(nextAddr, analysisSet, false);
                cmd.applyTo(currentProgram);
                if (listing.getInstructionAt(nextAddr) != null) fixed++;
            } catch (Exception e) {}
        }
        return fixed;
    }

    private static boolean hasDelaySlot(int word) {
        int op6 = (word >>> 26) & 0x3F;
        if (op6 == 0x1A || op6 == 0x1B || op6 == 0x1D || op6 == 0x1F ||
            op6 == 0x2D || op6 == 0x10) {
            return true;
        }
        if (op6 == 0x13) {
            int escop = word & 0x7;
            return escop == 0x2; // calli
        }
        return false;
    }

    // Follow flow targets from decoded instructions that aren't yet decoded.
    private int seedFromDecodedFlows() throws Exception {
        int seeded = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();

            for (Address target : insn.getFlows()) {
                if (target == null) continue;
                if (!analysisSet.contains(target)) continue;
                if (!isCandidateTargetAddress(target.getOffset())) continue;
                if (listing.getInstructionAt(target) != null) continue;

                DisassembleCommand cmd = new DisassembleCommand(target, analysisSet, true);
                cmd.applyTo(currentProgram);
                if (listing.getInstructionAt(target) != null) seeded++;
            }
        }
        return seeded;
    }

    private void parseScriptArgs(String[] scriptArgs) {
        if (scriptArgs == null) return;
        for (String raw : scriptArgs) {
            if (raw == null) continue;
            String arg = raw.trim();
            if (arg.isEmpty()) continue;
            if (arg.startsWith("--seed-map=")) {
                String value = arg.substring("--seed-map=".length()).trim();
                if (!value.isEmpty() && !value.equals("-")) seedMapPath = value;
                continue;
            }
            if (seedMapPath == null && !arg.equals("-")) {
                seedMapPath = arg;
            }
        }
    }

    private void loadSeedMap() {
        allowRanges.clear();
        denyRanges.clear();
        if (seedMapPath == null) return;

        try {
            String json = java.nio.file.Files.readString(java.nio.file.Paths.get(seedMapPath));
            allowRanges = parseRangeArray(json, "allow_ranges", "allow");
            denyRanges = parseRangeArray(json, "deny_ranges", "deny");
        } catch (Exception e) {
            printerr("Failed to read recovery map: " + seedMapPath + " (" + e.getMessage() + ")");
            allowRanges.clear();
            denyRanges.clear();
        }
    }

    private List<AddressRange> parseRangeArray(String json, String key, String defaultLabel) {
        List<AddressRange> ranges = new ArrayList<>();
        String body = extractArrayBody(json, key);
        if (body == null) return ranges;

        Matcher objectMatcher = Pattern.compile("\\{(.*?)\\}", Pattern.DOTALL).matcher(body);
        while (objectMatcher.find()) {
            String obj = objectMatcher.group(1);
            Long start = parseAddressField(obj, "start");
            Long end = parseAddressField(obj, "end");
            if (start == null || end == null) continue;

            String label = parseStringField(obj, "name");
            if (label == null) label = parseStringField(obj, "label");
            if (label == null) label = parseStringField(obj, "reason");
            if (label == null) label = defaultLabel;

            ranges.add(new AddressRange(start, end, label));
        }
        return ranges;
    }

    private void buildAnalysisSet() {
        analysisSet = new AddressSet();
        for (long[] r : execRanges) {
            long start = r[0];
            long end = r[1];
            long off = start;
            while (off <= end - 3) {
                if (!isCandidateAddress(off)) {
                    off += 4;
                    continue;
                }

                long runStart = off;
                off += 4;
                while (off <= end - 3 && isCandidateAddress(off)) {
                    off += 4;
                }
                long runEnd = off - 1;
                try {
                    analysisSet.add(space.getAddress(runStart), space.getAddress(runEnd));
                } catch (Exception e) {}
            }
        }
    }

    private static String extractArrayBody(String json, String key) {
        String pattern = "\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[(.*?)\\]";
        Matcher m = Pattern.compile(pattern, Pattern.DOTALL).matcher(json);
        if (!m.find()) return null;
        return m.group(1);
    }

    private static String parseStringField(String objectBody, String key) {
        String pattern = "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"";
        Matcher m = Pattern.compile(pattern, Pattern.DOTALL).matcher(objectBody);
        return m.find() ? m.group(1) : null;
    }

    private static Long parseAddressField(String objectBody, String key) {
        String pattern = "\"" + Pattern.quote(key) + "\"\\s*:\\s*(\"(?:0[xX][0-9a-fA-F]+|[0-9]+)\"|0[xX][0-9a-fA-F]+|[0-9]+)";
        Matcher m = Pattern.compile(pattern).matcher(objectBody);
        if (!m.find()) return null;
        String raw = m.group(1).trim();
        if (raw.startsWith("\"") && raw.endsWith("\"") && raw.length() >= 2) {
            raw = raw.substring(1, raw.length() - 1);
        }
        try {
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                return Long.parseUnsignedLong(raw.substring(2), 16);
            }
            return Long.parseUnsignedLong(raw, 10);
        } catch (Exception e) {
            return null;
        }
    }

    // Detect embedded non-i860 Mach-O objects within executable blocks.
    // Scans for Mach-O magic and parses LC_SEGMENT to compute actual sizes.
    private List<long[]> detectEmbeddedObjects() throws Exception {
        List<long[]> objects = new ArrayList<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            long blockSize = endOff - startOff + 1;
            if (blockSize > Integer.MAX_VALUE) continue;

            byte[] bytes = new byte[(int)blockSize];
            block.getBytes(block.getStart(), bytes);

            List<long[]> magics = new ArrayList<>();
            for (int i = 0; i < bytes.length - 28; i += 4) {
                int wordBE = ((bytes[i] & 0xFF) << 24) | ((bytes[i+1] & 0xFF) << 16)
                           | ((bytes[i+2] & 0xFF) << 8) | (bytes[i+3] & 0xFF);

                boolean isBE = (wordBE == 0xFEEDFACE);
                boolean isLE = (wordBE == 0xCEFAEDFE);
                if (!isBE && !isLE) continue;

                long addr = startOff + i;
                int cpuType;
                if (isBE) {
                    cpuType = ((bytes[i+4] & 0xFF) << 24) | ((bytes[i+5] & 0xFF) << 16)
                            | ((bytes[i+6] & 0xFF) << 8) | (bytes[i+7] & 0xFF);
                } else {
                    cpuType = (bytes[i+4] & 0xFF) | ((bytes[i+5] & 0xFF) << 8)
                            | ((bytes[i+6] & 0xFF) << 16) | ((bytes[i+7] & 0xFF) << 24);
                }
                magics.add(new long[]{addr, cpuType});
            }

            for (int m = 0; m < magics.size(); m++) {
                long addr = magics.get(m)[0];
                int cpuType = (int)magics.get(m)[1];

                if (addr == startOff) continue; // skip primary binary header
                if (cpuType == 15) continue;     // skip i860 objects

                int base = (int)(addr - startOff);
                boolean objBE;
                {
                    int w = ((bytes[base] & 0xFF) << 24) | ((bytes[base+1] & 0xFF) << 16)
                          | ((bytes[base+2] & 0xFF) << 8) | (bytes[base+3] & 0xFF);
                    objBE = (w == 0xFEEDFACE);
                }

                int sizeOfCmds = readMachInt(bytes, base + 20, objBE);
                int ncmds = readMachInt(bytes, base + 16, objBE);

                long maxFileEnd = 28 + sizeOfCmds;
                int cmdOff = base + 28;
                for (int c = 0; c < ncmds && cmdOff + 8 <= bytes.length; c++) {
                    int cmd = readMachInt(bytes, cmdOff, objBE);
                    int cmdSize = readMachInt(bytes, cmdOff + 4, objBE);
                    if (cmdSize < 8) break;

                    if (cmd == 1 && cmdOff + 40 <= bytes.length) {
                        int fileOff = readMachInt(bytes, cmdOff + 32, objBE);
                        int fileSize = readMachInt(bytes, cmdOff + 36, objBE);
                        long segEnd = (long)fileOff + fileSize;
                        if (segEnd > maxFileEnd) maxFileEnd = segEnd;
                    }
                    cmdOff += cmdSize;
                }

                long objEnd = Math.min(addr + maxFileEnd - 1, endOff);
                objects.add(new long[]{addr, objEnd});
            }
        }

        if (objects.size() > 1) {
            objects.sort((a, b) -> Long.compare(a[0], b[0]));
            List<long[]> merged = new ArrayList<>();
            long[] current = objects.get(0);
            for (int i = 1; i < objects.size(); i++) {
                long[] next = objects.get(i);
                if (next[0] <= current[1] + 1) {
                    current[1] = Math.max(current[1], next[1]);
                } else {
                    merged.add(current);
                    current = next;
                }
            }
            merged.add(current);
            return merged;
        }
        return objects;
    }

    private boolean isInEmbeddedObject(long addr) {
        for (long[] obj : embeddedObjects) {
            if (addr >= obj[0] && addr <= obj[1]) return true;
        }
        return false;
    }

    private boolean isInAllowedRanges(long addr) {
        if (allowRanges.isEmpty()) return true;
        for (AddressRange r : allowRanges) {
            if (addr >= r.start && addr <= r.end) return true;
        }
        return false;
    }

    private boolean isInDeniedRanges(long addr) {
        for (AddressRange r : denyRanges) {
            if (addr >= r.start && addr <= r.end) return true;
        }
        return false;
    }

    private boolean isCandidateAddress(long addr) {
        if (!isInExecRange(addr)) return false;
        if (isInEmbeddedObject(addr)) return false;
        if (!isInAllowedRanges(addr)) return false;
        if (isInDeniedRanges(addr)) return false;
        return true;
    }

    private boolean isCandidateTargetAddress(long addr) {
        if ((addr & 3) != 0) return false;
        return isCandidateAddress(addr);
    }

    private boolean isInExecRange(long addr) {
        for (long[] r : execRanges) {
            if (addr >= r[0] && addr <= r[1]) return true;
        }
        return false;
    }

    private int countInstructions() {
        int count = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) { ii.next(); count++; }
        return count;
    }

    private static int readWordLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
             | ((data[offset+1] & 0xFF) << 8)
             | ((data[offset+2] & 0xFF) << 16)
             | ((data[offset+3] & 0xFF) << 24);
    }

    private static int readMachInt(byte[] data, int offset, boolean bigEndian) {
        if (bigEndian) {
            return ((data[offset] & 0xFF) << 24) | ((data[offset+1] & 0xFF) << 16)
                 | ((data[offset+2] & 0xFF) << 8) | (data[offset+3] & 0xFF);
        } else {
            return (data[offset] & 0xFF) | ((data[offset+1] & 0xFF) << 8)
                 | ((data[offset+2] & 0xFF) << 16) | ((data[offset+3] & 0xFF) << 24);
        }
    }
}
