// Post-analysis script for i860 Mach-O binaries.
// Worklist-based seed discovery + recursive descent disassembly.
//
// Seeds come from:
//   - Raw-byte scanning: call/br targets, prologue patterns, orh+or address loads
//   - Data section pointers into executable range
//   - Decoded instruction flow targets (incremental)
//   - Post-return boundaries (incremental)
//
// Key optimizations:
//   - All raw-byte candidates collected once upfront (no rescanning)
//   - Worklist with failure cache (never retry failed seeds)
//   - Delay-slot closure after each round (fixes pcode errors at code/data edges)
//   - Incremental flow/post-return discovery (only newly decoded instructions)
//
// Run as -postScript after I860Import.java + auto-analysis.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class I860Analyze extends GhidraScript {

    private Listing listing;
    private Memory memory;
    private AddressSpace space;
    private AddressSet execSet;
    private AddressSet analysisSet;
    private List<long[]> execRanges;
    private List<long[]> embeddedObjects;
    private String rustXrefPath = null;
    private int rustXrefMinConfidence = 75;
    private Set<String> rustXrefKinds =
        new HashSet<>(Arrays.asList("Call", "BranchTaken", "Jump"));
    private int minLowConfidenceInsnRun = 4;
    private int minLowConfidenceFuncBytes = 64;
    private boolean requirePointerFlow = false;
    private String seedMapPath = null;
    private List<AddressRange> allowRanges = new ArrayList<>();
    private List<AddressRange> denyRanges = new ArrayList<>();
    private List<Seed> curatedSeedDefs = new ArrayList<>();
    private int functionsCreated = 0;

    // Incremental tracking: avoid re-checking instructions across rounds
    private Set<Long> flowChecked = new HashSet<>();
    private Set<Long> retChecked = new HashSet<>();

    private static final Set<String> HIGH_CONFIDENCE_FN_SOURCES = new HashSet<>(
        Arrays.asList(
            "entry",
            "call/br",
            "curated",
            "rust-xref-call",
            "strategy-call",
            "prologue",
            "strategy-prologue",
            "addr-load"
        )
    );

    static class Seed {
        final long addr;
        final boolean createFunction;
        final String source;
        Seed(long addr, boolean createFunction, String source) {
            this.addr = addr;
            this.createFunction = createFunction;
            this.source = source;
        }
    }

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
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        parseScriptArgs(getScriptArgs());

        // Build executable address set and ranges
        execSet = new AddressSet();
        execRanges = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute()) {
                execSet.add(block.getStart(), block.getEnd());
                execRanges.add(new long[]{block.getStart().getOffset(), block.getEnd().getOffset()});
            }
        }

        // Detect embedded non-i860 Mach-O objects in __text
        embeddedObjects = detectEmbeddedObjects();
        loadSeedMap();
        buildAnalysisSet();

        printf("=== I860Analyze postScript ===%n");
        printf("Embedded non-i860 objects: %d%n", embeddedObjects.size());
        for (long[] obj : embeddedObjects) {
            printf("  %08X - %08X (%,d bytes)%n", obj[0], obj[1], obj[1] - obj[0]);
        }
        printf("Analysis set ranges: %d%n", analysisSet.getNumAddressRanges());

        int baseInsns = countInstructions();
        printf("Instructions from preScript + auto-analysis: %d%n", baseInsns);
        if (rustXrefPath != null) {
            printf("Rust xref file: %s (min confidence %d, kinds=%s)%n",
                rustXrefPath, rustXrefMinConfidence, new TreeSet<>(rustXrefKinds));
        }
        if (seedMapPath != null) {
            printf("Recovery map: %s (allow=%d, deny=%d, curated-seeds=%d)%n",
                   seedMapPath, allowRanges.size(), denyRanges.size(), curatedSeedDefs.size());
            int cleared = clearDisallowedInstructions();
            if (cleared > 0) {
                printf("Cleared %d pre-decoded instructions outside analysis set%n", cleared);
            }
        }

        // Phase 1: Worklist-based seed discovery
        int[] seedCounts = worklistSeedDiscovery();

        // Phase 2: Function discovery on decoded instructions
        int s1 = strategyCallTargets();
        int s2 = strategyProloguePatterns();
        int s3 = strategyPostReturn();
        int s4 = strategyDataPointers();

        printf("%nFunction discovery summary:%n");
        printf("  Call targets:       %d%n", s1);
        printf("  Prologue patterns:  %d%n", s2);
        printf("  Post-return:        %d%n", s3);
        printf("  Data pointers:      %d%n", s4);
        printf("  Total new:          %d%n", functionsCreated);

        // Phase 3: Validate functions
        int pruned = validateFunctions();
        printf("  Pruned (bad start):  %d%n", pruned);

        // Phase 4: Code/Data region map + report
        List<Region> regions = classifyRegions();
        generateReport(s1, s2, s3, s4, pruned, seedCounts, regions);
    }

    private void parseScriptArgs(String[] scriptArgs) {
        List<String> positional = new ArrayList<>();
        if (scriptArgs != null) {
            for (String raw : scriptArgs) {
                if (raw == null) continue;
                String arg = raw.trim();
                if (arg.isEmpty()) continue;
                if (arg.startsWith("--xrefs=")) {
                    String value = arg.substring("--xrefs=".length()).trim();
                    if (!value.isEmpty() && !value.equals("-")) rustXrefPath = value;
                    continue;
                }
                if (arg.startsWith("--xref-min=")) {
                    String value = arg.substring("--xref-min=".length()).trim();
                    if (isIntegerLiteral(value)) {
                        rustXrefMinConfidence = Integer.parseInt(value);
                    }
                    continue;
                }
                if (arg.startsWith("--xref-kinds=")) {
                    String value = arg.substring("--xref-kinds=".length()).trim();
                    Set<String> parsed = parseCsvSet(value);
                    if (!parsed.isEmpty()) rustXrefKinds = parsed;
                    continue;
                }
                if (arg.startsWith("--min-low-func-insns=")) {
                    String value = arg.substring("--min-low-func-insns=".length()).trim();
                    if (isIntegerLiteral(value)) {
                        minLowConfidenceInsnRun = Math.max(1, Integer.parseInt(value));
                    }
                    continue;
                }
                if (arg.startsWith("--min-low-func-bytes=")) {
                    String value = arg.substring("--min-low-func-bytes=".length()).trim();
                    if (isIntegerLiteral(value)) {
                        minLowConfidenceFuncBytes = Math.max(4, Integer.parseInt(value));
                    }
                    continue;
                }
                if (arg.startsWith("--require-pointer-flow=")) {
                    String value = arg.substring("--require-pointer-flow=".length()).trim();
                    Boolean parsed = parseBooleanLiteral(value);
                    if (parsed != null) requirePointerFlow = parsed.booleanValue();
                    continue;
                }
                if (arg.startsWith("--seed-map=")) {
                    String value = arg.substring("--seed-map=".length()).trim();
                    if (!value.isEmpty() && !value.equals("-")) seedMapPath = value;
                    continue;
                }
                positional.add(arg);
            }
        }

        // Backward-compatible positional parsing:
        //   arg0 = xrefs_json
        //   arg1 = xref_min OR recovery_map_json
        //   arg2 = recovery_map_json
        if (rustXrefPath == null && positional.size() >= 1) {
            String arg0 = positional.get(0);
            if (!arg0.equals("-")) rustXrefPath = arg0;
        }
        if (positional.size() >= 2) {
            String arg1 = positional.get(1);
            if (isIntegerLiteral(arg1)) {
                rustXrefMinConfidence = Integer.parseInt(arg1);
            } else if (seedMapPath == null && !arg1.equals("-")) {
                seedMapPath = arg1;
            }
        }
        if (positional.size() >= 3) {
            String arg2 = positional.get(2);
            if (seedMapPath == null && !arg2.equals("-")) {
                seedMapPath = arg2;
            }
        }
    }

    private void loadSeedMap() {
        allowRanges.clear();
        denyRanges.clear();
        curatedSeedDefs.clear();
        if (seedMapPath == null) return;

        try {
            String json = java.nio.file.Files.readString(java.nio.file.Paths.get(seedMapPath));
            allowRanges = parseRangeArray(json, "allow_ranges", "allow");
            denyRanges = parseRangeArray(json, "deny_ranges", "deny");
            curatedSeedDefs = parseSeedArray(json, "seeds");
        } catch (Exception e) {
            printerr("Failed to read recovery map: " + seedMapPath + " (" + e.getMessage() + ")");
            allowRanges.clear();
            denyRanges.clear();
            curatedSeedDefs.clear();
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

    private List<Seed> parseSeedArray(String json, String key) {
        List<Seed> seeds = new ArrayList<>();
        String body = extractArrayBody(json, key);
        if (body == null) return seeds;

        Matcher objectMatcher = Pattern.compile("\\{(.*?)\\}", Pattern.DOTALL).matcher(body);
        while (objectMatcher.find()) {
            String obj = objectMatcher.group(1);
            Long addr = parseAddressField(obj, "addr");
            if (addr == null) addr = parseAddressField(obj, "address");
            if (addr == null) continue;

            boolean createFunction = true;
            Boolean createFn = parseBooleanField(obj, "create_function");
            if (createFn == null) createFn = parseBooleanField(obj, "createFunction");
            if (createFn != null) createFunction = createFn.booleanValue();

            seeds.add(new Seed(addr, createFunction, "curated"));
        }
        return seeds;
    }

    private int clearDisallowedInstructions() {
        List<Address> toClear = new ArrayList<>();
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            Instruction insn = ii.next();
            long off = insn.getAddress().getOffset();
            if (!isCandidateAddress(off)) {
                toClear.add(insn.getAddress());
            }
        }

        int cleared = 0;
        for (Address addr : toClear) {
            Instruction insn = listing.getInstructionAt(addr);
            if (insn == null) continue;
            try {
                clearListing(addr, addr.add(insn.getLength() - 1));
                cleared++;
            } catch (Exception e) {}
        }
        return cleared;
    }

    // Build candidate-only disassembly set:
    //   executable ranges minus embedded objects / deny ranges / out-of-allow.
    // This ensures DisassembleCommand flow-follow cannot spill into masked regions.
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

    private static Boolean parseBooleanField(String objectBody, String key) {
        String pattern = "\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)";
        Matcher m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(objectBody);
        if (!m.find()) return null;
        return Boolean.valueOf(Boolean.parseBoolean(m.group(1)));
    }

    private static boolean isIntegerLiteral(String s) {
        if (s == null) return false;
        return s.matches("[0-9]+");
    }

    private static Boolean parseBooleanLiteral(String s) {
        if (s == null) return null;
        String v = s.trim().toLowerCase(Locale.ROOT);
        if ("true".equals(v) || "1".equals(v) || "yes".equals(v)) return Boolean.TRUE;
        if ("false".equals(v) || "0".equals(v) || "no".equals(v)) return Boolean.FALSE;
        return null;
    }

    private static Set<String> parseCsvSet(String csv) {
        Set<String> out = new HashSet<>();
        if (csv == null) return out;
        for (String token : csv.split(",")) {
            String t = token.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    // ==================== Worklist Seed Discovery ====================

    private int[] worklistSeedDiscovery() throws Exception {
        Set<Long> processed = new HashSet<>();
        Set<Long> failed = new HashSet<>();

        // Phase A: Collect ALL static candidates once (raw bytes don't change between rounds)
        List<Seed> curatedSeeds = collectCuratedSeedCandidates();
        List<Seed> rustXrefSeeds = collectRustXrefCandidates();
        List<Seed> callBrSeeds = collectCallBrCandidates();
        List<Seed> prologueSeeds = collectPrologueCandidates();
        List<Seed> addressLoadSeeds = collectAddressLoadCandidates();
        List<Seed> dataPointerSeeds = collectDataPointerCandidates();

        printf("  Static candidates: curated=%d, rust-xref=%d, call/br=%d, prologue=%d, addr-load=%d, data-ptr=%d%n",
               curatedSeeds.size(), rustXrefSeeds.size(), callBrSeeds.size(), prologueSeeds.size(),
               addressLoadSeeds.size(), dataPointerSeeds.size());

        // Build initial worklist. Curated seeds are highest confidence, then Rust
        // xrefs, then raw call/branch targets, then heuristic candidates.
        Deque<Seed> worklist = new ArrayDeque<>();
        worklist.addAll(curatedSeeds);
        worklist.addAll(rustXrefSeeds);
        worklist.addAll(callBrSeeds);
        worklist.addAll(prologueSeeds);
        worklist.addAll(addressLoadSeeds);
        worklist.addAll(dataPointerSeeds);

        // Per-source success counters
        Map<String, Integer> sourceSuccess = new LinkedHashMap<>();
        int round = 0;

        while (round < 30) {
            round++;
            if (monitor.isCancelled()) break;
            int beforeInsns = countInstructions();
            int roundSeeded = 0;

            // Process current worklist batch
            int batchSize = worklist.size();
            for (int i = 0; i < batchSize && !monitor.isCancelled(); i++) {
                Seed seed = worklist.poll();
                if (seed == null) break;
                if (processed.contains(seed.addr)) continue;
                processed.add(seed.addr);

                Address target = space.getAddress(seed.addr);
                if (listing.getInstructionAt(target) != null) {
                    // Already decoded by prior seed's flow following — just ensure function exists
                    if (seed.createFunction) tryCreateFunction(target, seed.source);
                    continue;
                }

                boolean success;
                if (seed.createFunction) {
                    success = disassembleAndCreate(target, seed.source);
                } else {
                    success = disassembleOnly(target);
                }

                if (success) {
                    roundSeeded++;
                    sourceSuccess.merge(seed.source, 1, Integer::sum);
                } else {
                    failed.add(seed.addr);
                }
            }

            // Fix orphan delay slots (decode missing PC+4 for delay-slot instructions)
            int delayFixed = fixOrphanDelaySlots();

            // Discover new candidates from decoded instruction flows (incremental)
            int flowAdded = addFlowCandidates(worklist, processed);

            // Discover post-return boundary candidates (incremental)
            int postRetAdded = addPostReturnCandidates(worklist, processed);

            int afterInsns = countInstructions();
            int delta = afterInsns - beforeInsns;

            printf("  Round %d: +%d insns, %d seeded, %d delay-fixed, +%d flow, +%d post-ret%n",
                   round, delta, roundSeeded, delayFixed, flowAdded, postRetAdded);

            if (delta == 0 && worklist.isEmpty()) break;
        }

        int totalInsns = countInstructions();
        printf("Seed discovery complete: %d rounds, %d instructions, %d failed%n",
               round, totalInsns, failed.size());
        for (Map.Entry<String, Integer> e : sourceSuccess.entrySet()) {
            printf("  %s: %d successful%n", e.getKey(), e.getValue());
        }

        // Return counts for report:
        // [flow, callBr, addrLoad, prologue, dataPtr, postReturn, rustXref, curated]
        return new int[]{
            sourceSuccess.getOrDefault("flow", 0),
            sourceSuccess.getOrDefault("call/br", 0),
            sourceSuccess.getOrDefault("addr-load", 0),
            sourceSuccess.getOrDefault("prologue", 0),
            sourceSuccess.getOrDefault("data-ptr", 0),
            sourceSuccess.getOrDefault("post-ret", 0),
            sourceSuccess.getOrDefault("rust-xref-call", 0) +
                sourceSuccess.getOrDefault("rust-xref-flow", 0),
            sourceSuccess.getOrDefault("curated", 0)
        };
    }

    // ==================== Candidate Collection (run once) ====================

    private List<Seed> collectCuratedSeedCandidates() {
        List<Seed> seeds = new ArrayList<>();
        if (curatedSeedDefs.isEmpty()) return seeds;

        Set<Long> seen = new HashSet<>();
        int rejected = 0;
        for (Seed seed : curatedSeedDefs) {
            if (!isCandidateTargetAddress(seed.addr)) {
                rejected++;
                continue;
            }
            if (!seen.add(seed.addr)) continue;
            seeds.add(new Seed(seed.addr, seed.createFunction, "curated"));
        }
        printf("  Curated seeds: %d usable, %d rejected by filters%n", seeds.size(), rejected);
        return seeds;
    }

    // Scan raw bytes of all executable blocks for 26-bit branch/call targets.
    // Opcodes 0x1A-0x1F: br, call, bc, bc.t, bnc, bnc.t
    // Target = PC + (sign_extend(bits[25:0]) << 2)
    // Only call targets (0x1B) get createFunction=true.
    private List<Seed> collectCallBrCandidates() throws Exception {
        List<Seed> seeds = new ArrayList<>();
        Set<Long> seen = new HashSet<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            byte[] bytes = new byte[(int)(endOff - startOff + 1)];
            block.getBytes(block.getStart(), bytes);

            for (int i = 0; i < bytes.length - 3; i += 4) {
                long srcAddr = startOff + i;
                if (!isCandidateAddress(srcAddr)) continue;

                int word = readWordLE(bytes, i);
                int op6 = (word >>> 26) & 0x3F;
                if (op6 < 0x1A || op6 > 0x1F) continue;

                int offset26 = word & 0x03FFFFFF;
                if ((offset26 & 0x02000000) != 0) offset26 |= 0xFC000000;

                long target = srcAddr + ((long)offset26 << 2);
                if (!isCandidateTargetAddress(target)) continue;
                if (seen.contains(target)) continue;
                seen.add(target);

                boolean isCall = (op6 == 0x1B);
                seeds.add(new Seed(target, isCall, "call/br"));
            }
        }
        return seeds;
    }

    // Scan raw bytes for prologue patterns:
    //   subs 0x0,r1,rN  (op6=0x27, src2=1, simm16=0)
    //   addu -N,sp,sp   (op6=0x21, sp=r2 GCC or r29 SPEA, -4096<=simm16<0)
    private List<Seed> collectPrologueCandidates() throws Exception {
        List<Seed> seeds = new ArrayList<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            byte[] bytes = new byte[(int)(endOff - startOff + 1)];
            block.getBytes(block.getStart(), bytes);

            for (int i = 0; i < bytes.length - 3; i += 4) {
                long srcAddr = startOff + i;
                if (!isCandidateAddress(srcAddr)) continue;

                int word = readWordLE(bytes, i);
                if (isProloguePattern(word)) {
                    seeds.add(new Seed(srcAddr, true, "prologue"));
                }
            }
        }
        return seeds;
    }

    // Scan raw bytes for orh+or pairs constructing executable addresses.
    //   orh hi, r0, rN   (op6=0x3B, src2=0)
    //   or  lo, rN, rN   (op6=0x39, src2=dest=same as orh dest)
    private List<Seed> collectAddressLoadCandidates() throws Exception {
        List<Seed> seeds = new ArrayList<>();
        Set<Long> seen = new HashSet<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            byte[] bytes = new byte[(int)(endOff - startOff + 1)];
            block.getBytes(block.getStart(), bytes);

            for (int i = 0; i < bytes.length - 7; i += 4) {
                long srcAddr = startOff + i;
                if (!isCandidateAddress(srcAddr)) continue;

                int word1 = readWordLE(bytes, i);
                if (((word1 >>> 26) & 0x3F) != 0x3B) continue;
                if (((word1 >>> 21) & 0x1F) != 0) continue;

                int dest_1 = (word1 >>> 16) & 0x1F;
                if (dest_1 == 0) continue;
                int hi = word1 & 0xFFFF;

                int word2 = readWordLE(bytes, i + 4);
                if (((word2 >>> 26) & 0x3F) != 0x39) continue;
                if (((word2 >>> 21) & 0x1F) != dest_1) continue;
                if (((word2 >>> 16) & 0x1F) != dest_1) continue;

                long target = ((long)hi << 16) | (word2 & 0xFFFF);
                if (!isCandidateTargetAddress(target)) continue;
                if (seen.contains(target)) continue;
                seen.add(target);

                seeds.add(new Seed(target, true, "addr-load"));
            }
        }
        return seeds;
    }

    // Scan writable data sections for 4-byte pointers into executable range.
    private List<Seed> collectDataPointerCandidates() throws Exception {
        List<Seed> seeds = new ArrayList<>();
        Set<Long> seen = new HashSet<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isWrite() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            byte[] bytes = new byte[(int)(endOff - startOff + 1)];
            block.getBytes(block.getStart(), bytes);

            for (int i = 0; i < bytes.length - 3; i += 4) {
                long ptr = readWordLE(bytes, i) & 0xFFFFFFFFL;
                if (!isCandidateTargetAddress(ptr)) continue;
                if (seen.contains(ptr)) continue;
                seen.add(ptr);

                // Pointer-derived targets are low confidence by default:
                // decode first, then gate function creation with stricter checks.
                seeds.add(new Seed(ptr, false, "data-ptr"));
            }
        }
        return seeds;
    }

    // Parse Rust disassembler xrefs JSON and seed selected resolved flow targets.
    // Expected object entries:
    //   {"from":..., "to":..., "kind":"Call|BranchTaken|Jump|...", "confidence":...}
    private List<Seed> collectRustXrefCandidates() {
        List<Seed> seeds = new ArrayList<>();
        if (rustXrefPath == null) return seeds;

        Set<Long> seen = new HashSet<>();
        try {
            String json = java.nio.file.Files.readString(java.nio.file.Paths.get(rustXrefPath));
            Pattern xrefPattern = Pattern.compile(
                "\\{\\s*\"from\"\\s*:\\s*([0-9]+)\\s*,\\s*\"to\"\\s*:\\s*(null|[0-9]+)\\s*,\\s*\"kind\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"confidence\"\\s*:\\s*([0-9]+)\\s*\\}",
                Pattern.DOTALL
            );

            int parsed = 0;
            int callSeeds = 0;
            int flowSeeds = 0;
            Matcher m = xrefPattern.matcher(json);
            while (m.find()) {
                parsed++;
                String toStr = m.group(2);
                String kind = m.group(3);
                int confidence = Integer.parseInt(m.group(4));

                if (!rustXrefKinds.contains(kind)) continue;
                if ("null".equals(toStr)) continue;
                if (confidence < rustXrefMinConfidence) continue;

                long target = Long.parseUnsignedLong(toStr);
                if (!isCandidateTargetAddress(target)) continue;
                if (!seen.add(target)) continue;

                boolean isCall = "Call".equals(kind);
                if (isCall) callSeeds++;
                else flowSeeds++;

                // Calls can start functions; branch/jump targets are decode-only seeds.
                String source = isCall ? "rust-xref-call" : "rust-xref-flow";
                seeds.add(new Seed(target, isCall, source));
            }
            printf("  Rust xrefs parsed: %d entries, %d usable targets (call=%d, flow=%d)%n",
                parsed, seeds.size(), callSeeds, flowSeeds);
        } catch (Exception e) {
            printerr("Failed to read Rust xref file: " + rustXrefPath + " (" + e.getMessage() + ")");
        }
        return seeds;
    }

    // ==================== Incremental Candidate Discovery ====================

    // Scan decoded instructions for unresolved flow targets. Only checks
    // instructions not yet examined (tracked by flowChecked set).
    private int addFlowCandidates(Deque<Seed> worklist, Set<Long> processed) {
        int added = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            long insAddr = insn.getAddress().getOffset();
            if (flowChecked.contains(insAddr)) continue;
            flowChecked.add(insAddr);

            for (Address target : insn.getFlows()) {
                if (target == null) continue;
                if (!analysisSet.contains(target)) continue;
                long tAddr = target.getOffset();
                if (!isCandidateTargetAddress(tAddr)) continue;
                if (processed.contains(tAddr)) continue;

                String mnem = insn.getMnemonicString();
                boolean isCall = mnem.contains("call");
                worklist.add(new Seed(tAddr, isCall, "flow"));
                added++;
            }
        }
        return added;
    }

    // Scan for ret instructions in confirmed functions; seed after ret + delay slot.
    // Only checks return instructions not yet examined (tracked by retChecked set).
    private int addPostReturnCandidates(Deque<Seed> worklist, Set<Long> processed) {
        int added = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            if (!isReturn(insn)) continue;

            long retAddr = insn.getAddress().getOffset();
            if (retChecked.contains(retAddr)) continue;
            retChecked.add(retAddr);

            if (listing.getFunctionContaining(insn.getAddress()) == null) continue;

            // Address after ret (4 bytes) + delay slot (4 bytes) = +8
            Address afterDelaySlot = insn.getAddress().add(8);
            if (!analysisSet.contains(afterDelaySlot)) continue;
            long afterAddr = afterDelaySlot.getOffset();
            if (!isCandidateTargetAddress(afterAddr)) continue;
            if (processed.contains(afterAddr)) continue;
            if (listing.getInstructionAt(afterDelaySlot) == null) continue;
            if (listing.getFunctionContaining(afterDelaySlot) != null) continue;

            worklist.add(new Seed(afterAddr, true, "post-ret"));
            added++;
        }
        return added;
    }

    // ==================== Delay-Slot Closure ====================

    // Decode missing delay-slot instructions at code/data boundaries.
    // i860 delay-slot opcodes (raw decode):
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

                // Decode single instruction at PC+4 (no flow following — just the delay slot)
                AddressSet singleInsn = new AddressSet(nextAddr, nextAddr.add(3));
                DisassembleCommand cmd = new DisassembleCommand(nextAddr, singleInsn, false);
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

    // ==================== Disassembly Helpers ====================

    private boolean disassembleAndCreate(Address seed, String source) {
        if (!isCandidateTargetAddress(seed.getOffset())) return false;
        try {
            DisassembleCommand cmd = new DisassembleCommand(seed, analysisSet, true);
            cmd.applyTo(currentProgram);
            if (listing.getInstructionAt(seed) == null) return false;
            return tryCreateFunction(seed, source);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean disassembleOnly(Address seed) {
        if (!isCandidateTargetAddress(seed.getOffset())) return false;
        try {
            DisassembleCommand cmd = new DisassembleCommand(seed, analysisSet, true);
            cmd.applyTo(currentProgram);
            return listing.getInstructionAt(seed) != null;
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== Function Discovery ====================

    // Strategy 1: Call targets from decoded instructions
    private int strategyCallTargets() {
        printf("%nStrategy 1: Call targets...%n");
        int count = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            String mnemonic = insn.getMnemonicString();
            if (mnemonic.contains("call")) {
                for (Address target : insn.getFlows()) {
                    if (target != null && memory.contains(target)) {
                        if (tryCreateFunction(target, "strategy-call")) count++;
                    }
                }
            }
        }
        printf("  Found %d functions from call targets%n", count);
        return count;
    }

    // Strategy 2: Prologue patterns on decoded instructions
    private int strategyProloguePatterns() {
        printf("Strategy 2: Prologue patterns...%n");
        int count = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            try {
                int word = memory.getInt(insn.getAddress());
                if (isProloguePattern(word)) {
                    if (tryCreateFunction(insn.getAddress(), "strategy-prologue")) count++;
                }
            } catch (Exception e) {}
        }
        printf("  Found %d functions from prologue patterns%n", count);
        return count;
    }

    // Strategy 3: Post-return boundaries
    private int strategyPostReturn() {
        printf("Strategy 3: Post-return boundaries...%n");
        int count = 0;
        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction insn = ii.next();
            if (!isReturn(insn)) continue;
            if (listing.getFunctionContaining(insn.getAddress()) == null) continue;

            // Skip delay slot + get next instruction
            if (!ii.hasNext()) break;
            ii.next();
            if (!ii.hasNext()) break;
            Instruction nextInsn = ii.next();
            if (tryCreateFunction(nextInsn.getAddress(), "strategy-post-ret")) count++;
        }
        printf("  Found %d functions from post-return boundaries%n", count);
        return count;
    }

    // Strategy 4: Data section pointers to decoded instructions
    private int strategyDataPointers() {
        printf("Strategy 4: Data pointers...%n");
        int count = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isWrite() || !block.isInitialized()) continue;
            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            for (long off = startOff; off <= endOff - 3; off += 4) {
                if (monitor.isCancelled()) break;
                try {
                    Address addr = space.getAddress(off);
                    int word = memory.getInt(addr);
                    long ptr = word & 0xFFFFFFFFL;
                    if (!isCandidateTargetAddress(ptr)) continue;
                    Address target = space.getAddress(ptr);
                    if (listing.getInstructionAt(target) != null) {
                        if (tryCreateFunction(target, "strategy-data-ptr")) count++;
                    }
                } catch (Exception e) {}
            }
        }
        printf("  Found %d functions from data pointers%n", count);
        return count;
    }

    // ==================== Helpers ====================

    private boolean isProloguePattern(int word) {
        int op6 = (word >>> 26) & 0x3F;
        int src2 = (word >>> 21) & 0x1F;
        int dest = (word >>> 16) & 0x1F;
        short simm16 = (short)(word & 0xFFFF);

        // subs 0x0,r1,rN — return address save
        if (op6 == 0x27 && src2 == 1 && simm16 == 0 && dest != 0) return true;

        // addu -N,sp,sp — stack frame allocation (-4096 <= N < 0)
        if (op6 == 0x21 && simm16 < 0 && simm16 >= -4096) {
            if (src2 == 2 && dest == 2) return true;   // GCC ABI (r2=sp)
            if (src2 == 29 && dest == 29) return true;  // SPEA ABI (r29=sp)
        }
        return false;
    }

    private boolean isReturn(Instruction insn) {
        String mnemonic = insn.getMnemonicString();
        if (mnemonic.equals("ret") || mnemonic.equals("_ret")) return true;
        if (!mnemonic.equals("bri") && !mnemonic.equals("_bri")) return false;
        try {
            int word = memory.getInt(insn.getAddress());
            int op6 = (word >>> 26) & 0x3F;
            int src1 = (word >>> 11) & 0x1F;
            return op6 == 0x10 && src1 == 1; // bri r1
        } catch (Exception e) {
            return false;
        }
    }

    private boolean tryCreateFunction(Address addr, String source) {
        if (source == null || source.isEmpty()) source = "unknown";
        if (!isCandidateTargetAddress(addr.getOffset())) return false;
        if (listing.getInstructionAt(addr) == null) return false;
        Function existing = listing.getFunctionContaining(addr);
        if (existing != null) return false;
        if (!passesFunctionStartGate(addr, source)) return false;
        try {
            createFunction(addr, null);

            Function created = listing.getFunctionContaining(addr);
            if (created == null || !created.getEntryPoint().equals(addr)) return false;

            // Low-confidence sources must clear a minimum size threshold.
            if (!isHighConfidenceFunctionSource(source)) {
                long size = created.getBody().getNumAddresses();
                if (size < minLowConfidenceFuncBytes) {
                    currentProgram.getFunctionManager().removeFunction(created.getEntryPoint());
                    return false;
                }
            }

            functionsCreated++;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isHighConfidenceFunctionSource(String source) {
        return HIGH_CONFIDENCE_FN_SOURCES.contains(source);
    }

    private boolean passesFunctionStartGate(Address addr, String source) {
        if (isHighConfidenceFunctionSource(source)) return true;

        // For low-confidence sources, require a contiguous decoded run at start.
        if (!hasContiguousDecodedInstructions(addr, minLowConfidenceInsnRun)) return false;

        // Pointer and post-return heuristics must also have a structural signal.
        if (requirePointerFlow &&
            ("data-ptr".equals(source) || "strategy-data-ptr".equals(source) ||
             "post-ret".equals(source) || "strategy-post-ret".equals(source))) {
            return hasIncomingFlowReference(addr) || isPrologueAddress(addr);
        }
        return true;
    }

    private boolean hasContiguousDecodedInstructions(Address start, int minCount) {
        for (int i = 0; i < minCount; i++) {
            Address check = start.add((long)i * 4);
            if (!memory.contains(check)) return false;
            if (listing.getInstructionAt(check) == null) return false;
        }
        return true;
    }

    private boolean hasIncomingFlowReference(Address addr) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref == null) continue;
            Address from = ref.getFromAddress();
            if (from == null || !memory.contains(from)) continue;
            RefType type = ref.getReferenceType();
            if (type != null && type.isFlow()) return true;
        }
        return false;
    }

    private boolean isPrologueAddress(Address addr) {
        try {
            int word = memory.getInt(addr);
            return isProloguePattern(word);
        } catch (Exception e) {
            return false;
        }
    }

    // Validate functions: remove those where the first 4 instructions have gaps
    private int validateFunctions() {
        printf("%nValidating function starts...%n");
        int pruned = 0;
        List<Function> toRemove = new ArrayList<>();
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            Address addr = f.getEntryPoint();
            boolean valid = true;
            for (int i = 0; i < 4; i++) {
                Address check = space.getAddress(addr.getOffset() + (long)i * 4);
                if (!memory.contains(check)) { valid = false; break; }
                if (listing.getInstructionAt(check) == null) { valid = false; break; }
            }
            if (!valid) toRemove.add(f);
        }
        for (Function f : toRemove) {
            try {
                currentProgram.getFunctionManager().removeFunction(f.getEntryPoint());
                pruned++;
            } catch (Exception e) {}
        }
        printf("  Pruned %d functions with bad starts%n", pruned);
        return pruned;
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

    private int countFunctions() {
        int count = 0;
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) { fi.next(); count++; }
        return count;
    }

    // ==================== Embedded Object Detection ====================

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

            // First pass: find all Mach-O magic positions and CPU types
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

            // Second pass: for non-i860 objects, parse LC_SEGMENT to compute size
            for (int m = 0; m < magics.size(); m++) {
                long addr = magics.get(m)[0];
                int cpuType = (int)magics.get(m)[1];

                if (addr == startOff) continue; // primary binary header
                if (cpuType == 15) continue;     // i860

                int base = (int)(addr - startOff);
                boolean objBE;
                {
                    int w = ((bytes[base] & 0xFF) << 24) | ((bytes[base+1] & 0xFF) << 16)
                          | ((bytes[base+2] & 0xFF) << 8) | (bytes[base+3] & 0xFF);
                    objBE = (w == 0xFEEDFACE);
                }

                int ncmds = readMachInt(bytes, base + 16, objBE);
                int sizeOfCmds = readMachInt(bytes, base + 20, objBE);

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

        // Merge overlapping/adjacent exclusion regions
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

    // ==================== Byte Readers ====================

    private static int readMachInt(byte[] data, int offset, boolean bigEndian) {
        if (bigEndian) {
            return ((data[offset] & 0xFF) << 24) | ((data[offset+1] & 0xFF) << 16)
                 | ((data[offset+2] & 0xFF) << 8) | (data[offset+3] & 0xFF);
        } else {
            return (data[offset] & 0xFF) | ((data[offset+1] & 0xFF) << 8)
                 | ((data[offset+2] & 0xFF) << 16) | ((data[offset+3] & 0xFF) << 24);
        }
    }

    private static int readWordLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
             | ((data[offset+1] & 0xFF) << 8)
             | ((data[offset+2] & 0xFF) << 16)
             | ((data[offset+3] & 0xFF) << 24);
    }

    // ==================== Classification + Report ====================

    private List<Region> classifyRegions() {
        printf("%nCode/Data classification...%n");
        List<Region> regions = new ArrayList<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;
            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();

            boolean inCode = false;
            long regionStart = startOff;

            for (long off = startOff; off <= endOff - 3; off += 4) {
                Address addr = space.getAddress(off);
                boolean hasInsn = listing.getInstructionAt(addr) != null;

                if (off == startOff) {
                    inCode = hasInsn;
                    regionStart = off;
                } else if (hasInsn != inCode) {
                    regions.add(new Region(regionStart, off - 4, inCode));
                    inCode = hasInsn;
                    regionStart = off;
                }
            }
            long lastAligned = endOff - ((endOff - startOff + 1) % 4);
            if (lastAligned < startOff) lastAligned = startOff;
            regions.add(new Region(regionStart, lastAligned, inCode));
        }

        int codeRegions = 0, dataRegions = 0;
        for (Region r : regions) {
            if (r.isCode) codeRegions++; else dataRegions++;
        }
        printf("  %d regions: %d code, %d data%n", regions.size(), codeRegions, dataRegions);
        return regions;
    }

    private void generateReport(int s1, int s2, int s3, int s4, int pruned,
                                int[] seedCounts, List<Region> regions) throws Exception {
        int totalInsn = countInstructions();
        int totalFunc = countFunctions();
        List<Function> functions = new ArrayList<>();
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) functions.add(fi.next());

        long codeBytes = 0, dataBytes = 0;
        for (Region r : regions) {
            long size = r.end - r.start + 4;
            if (r.isCode) codeBytes += size; else dataBytes += size;
        }

        long totalExecBytes = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute()) totalExecBytes += block.getSize();
        }
        double coverage = totalExecBytes > 0 ? (codeBytes * 100.0 / totalExecBytes) : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("=== i860 Kernel Analysis Report (Recursive Descent) ===\n\n");

        sb.append("--- Summary ---\n");
        sb.append(String.format("Program:      %s\n", currentProgram.getName()));
        sb.append(String.format("Language:     %s\n", currentProgram.getLanguageID()));
        sb.append(String.format("Compiler:     %s\n", currentProgram.getCompilerSpec().getCompilerSpecID()));
        sb.append(String.format("Instructions: %,d\n", totalInsn));
        sb.append(String.format("Functions:    %,d\n", totalFunc));
        sb.append(String.format("Code bytes:   %,d\n", codeBytes));
        sb.append(String.format("Data bytes:   %,d (in executable blocks)\n", dataBytes));
        sb.append(String.format("Coverage:     %.1f%%\n", coverage));
        sb.append("\n");

        sb.append("--- Seed Discovery ---\n");
        if (seedMapPath != null) {
            sb.append(String.format("Recovery map:      %s\n", seedMapPath));
            sb.append(String.format("Allow ranges:      %d\n", allowRanges.size()));
            sb.append(String.format("Deny ranges:       %d\n", denyRanges.size()));
            sb.append(String.format("Curated seed defs: %d\n", curatedSeedDefs.size()));
        }
        sb.append(String.format("Decoded flows:     %d\n", seedCounts[0]));
        sb.append(String.format("Call/br targets:   %d\n", seedCounts[1]));
        sb.append(String.format("Address loads:     %d\n", seedCounts[2]));
        sb.append(String.format("Prologue seeds:    %d\n", seedCounts[3]));
        sb.append(String.format("Pointer seeds:     %d\n", seedCounts[4]));
        sb.append(String.format("Post-return seeds: %d\n", seedCounts[5]));
        if (seedCounts.length > 6) {
            sb.append(String.format("Rust xref seeds:   %d\n", seedCounts[6]));
        }
        if (seedCounts.length > 7) {
            sb.append(String.format("Curated seeds:     %d\n", seedCounts[7]));
        }
        sb.append("\n");

        sb.append("--- Function Discovery ---\n");
        sb.append(String.format("Call targets:       %d\n", s1));
        sb.append(String.format("Prologue patterns:  %d\n", s2));
        sb.append(String.format("Post-return:        %d\n", s3));
        sb.append(String.format("Data pointers:      %d\n", s4));
        sb.append(String.format("Total new:          %d\n", functionsCreated));
        sb.append(String.format("Pruned (bad start): %d\n", pruned));
        sb.append("\n");

        sb.append("--- Functions ---\n");
        sb.append(String.format("%-12s  %-8s  %-30s  %s\n", "Address", "Size", "Name", "First Insn"));
        sb.append(String.format("%-12s  %-8s  %-30s  %s\n", "-------", "----", "----", "----------"));
        for (Function f : functions) {
            Address fAddr = f.getEntryPoint();
            long size = f.getBody().getNumAddresses();
            String name = f.getName();
            Instruction firstInsn = listing.getInstructionAt(fAddr);
            String firstMnem = firstInsn != null ? firstInsn.toString() : "?";
            if (firstMnem.length() > 40) firstMnem = firstMnem.substring(0, 40);
            sb.append(String.format("%-12s  %-8d  %-30s  %s\n", fAddr, size, name, firstMnem));
        }
        sb.append("\n");

        sb.append("--- Code/Data Regions (executable blocks) ---\n");
        sb.append(String.format("%-12s  %-12s  %-10s  %s\n", "Start", "End", "Size", "Type"));
        sb.append(String.format("%-12s  %-12s  %-10s  %s\n", "-----", "---", "----", "----"));
        for (Region r : regions) {
            long size = r.end - r.start + 4;
            sb.append(String.format("%08X      %08X      %-10d  %s\n",
                      r.start, r.end, size, r.isCode ? "CODE" : "DATA"));
        }
        sb.append("\n");

        sb.append("--- Memory Blocks ---\n");
        for (MemoryBlock block : memory.getBlocks()) {
            sb.append(String.format("  %-20s %08x-%08x  %,8d bytes  %s%s%s\n",
                block.getName(),
                block.getStart().getOffset(),
                block.getEnd().getOffset(),
                block.getSize(),
                block.isRead() ? "r" : "-",
                block.isWrite() ? "w" : "-",
                block.isExecute() ? "x" : "-"));
        }

        String report = sb.toString();
        printf("%n%s", report);

        String reportPath = "/tmp/i860_kernel_report.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(reportPath));
        pw.print(report);
        pw.close();
        printf("Report written to: %s%n", reportPath);
    }

    static class Region {
        long start, end;
        boolean isCode;
        Region(long start, long end, boolean isCode) {
            this.start = start; this.end = end; this.isCode = isCode;
        }
    }
}
