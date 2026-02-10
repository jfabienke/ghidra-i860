// Export structured fact-pack artifacts for LLM swarm intent analysis.
//
// Output files (JSON/JSONL):
//   - meta.json
//   - functions.jsonl
//   - blocks.jsonl
//   - edges.jsonl
//   - insns.jsonl
//   - refs.jsonl
//   - strings.jsonl
//   - dispatch_unresolved.jsonl
//
// Run as a postScript after I860Analyze.java.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.*;

public class ExportFactPack extends GhidraScript {
    private static final long U32_MASK = 0xFFFF_FFFFL;
    private static final long I860_MMIO_BASE = 0x0200_0000L;
    private static final long I860_MMIO_END = 0x0200_0FFFL;
    private static final long HOST_IO_BASE = 0xFF80_0000L;
    private static final long HOST_IO_END = 0xFF80_3FFFL;
    private static final long DP_BASE = 0xF000_0000L;
    private static final long DP_END = 0xF000_0FFFL;

    private Listing listing;
    private Memory memory;
    private AddressSpace space;

    private String outDirPath = null;
    private String seedMapPath = null;
    private String phase2Path = null;

    private List<long[]> execRanges = new ArrayList<>();
    private List<long[]> embeddedObjects = new ArrayList<>();

    private List<AddressRange> allowRanges = new ArrayList<>();
    private List<AddressRange> denyRanges = new ArrayList<>();
    private Set<Long> curatedSeeds = new HashSet<>();

    private Map<Long, StringRecord> stringRecords = new TreeMap<>();
    private Map<String, String> phase2DispatchClassByAddr = new HashMap<>();

    private static class AddressRange {
        final long start;
        final long end;
        final String label;

        AddressRange(long start, long end, String label) {
            if (start <= end) {
                this.start = start;
                this.end = end;
            }
            else {
                this.start = end;
                this.end = start;
            }
            this.label = label;
        }
    }

    private static class StringRecord {
        final long addr;
        final int length;
        final String value;

        StringRecord(long addr, int length, String value) {
            this.addr = addr;
            this.length = length;
            this.value = value;
        }
    }

    private static class ExportCounts {
        int functions = 0;
        int blocks = 0;
        int edges = 0;
        int insns = 0;
        int refs = 0;
        int strings = 0;
        int dispatchUnresolved = 0;
        long codeBytes = 0;
    }

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        parseScriptArgs(getScriptArgs());
        buildExecRanges();
        embeddedObjects = detectEmbeddedObjects();
        loadSeedMap();
        loadPhase2Hints();

        if (outDirPath == null || outDirPath.trim().isEmpty()) {
            String ts = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                .withZone(ZoneOffset.UTC)
                .format(Instant.now());
            outDirPath = "/tmp/factpack_" + currentProgram.getName() + "_" + ts;
        }

        Path outDir = Paths.get(outDirPath);
        Files.createDirectories(outDir);

        println("=== ExportFactPack ===");
        println("Output directory: " + outDir.toAbsolutePath());
        println("Seed map: " + (seedMapPath == null ? "(none)" : seedMapPath));
        println("Phase2 hints: " + (phase2Path == null ? "(none)" : phase2Path));

        ExportCounts counts = new ExportCounts();

        exportStrings(outDir.resolve("strings.jsonl"), counts);
        exportFunctions(outDir.resolve("functions.jsonl"), counts);
        exportBlocks(outDir.resolve("blocks.jsonl"), counts);
        exportInsnsEdgesRefsDispatch(
            outDir.resolve("insns.jsonl"),
            outDir.resolve("edges.jsonl"),
            outDir.resolve("refs.jsonl"),
            outDir.resolve("dispatch_unresolved.jsonl"),
            counts
        );
        exportMeta(outDir.resolve("meta.json"), counts);

        println("Fact pack export complete:");
        println("  functions: " + counts.functions);
        println("  blocks: " + counts.blocks);
        println("  edges: " + counts.edges);
        println("  insns: " + counts.insns);
        println("  refs: " + counts.refs);
        println("  strings: " + counts.strings);
        println("  dispatch_unresolved: " + counts.dispatchUnresolved);
        println("  code_bytes (decoded): " + counts.codeBytes);
    }

    // ==================== Argument Parsing ====================

    private void parseScriptArgs(String[] scriptArgs) {
        List<String> positional = new ArrayList<>();
        if (scriptArgs != null) {
            for (String raw : scriptArgs) {
                if (raw == null) continue;
                String arg = raw.trim();
                if (arg.isEmpty()) continue;

                if (arg.startsWith("--out=")) {
                    outDirPath = arg.substring("--out=".length()).trim();
                    continue;
                }
                if (arg.startsWith("--seed-map=")) {
                    String v = arg.substring("--seed-map=".length()).trim();
                    if (!v.isEmpty() && !v.equals("-")) seedMapPath = v;
                    continue;
                }
                if (arg.startsWith("--phase2=")) {
                    String v = arg.substring("--phase2=".length()).trim();
                    if (!v.isEmpty() && !v.equals("-")) phase2Path = v;
                    continue;
                }

                positional.add(arg);
            }
        }

        if (outDirPath == null && positional.size() >= 1) outDirPath = positional.get(0);
        if (seedMapPath == null && positional.size() >= 2 && !"-".equals(positional.get(1))) {
            seedMapPath = positional.get(1);
        }
        if (phase2Path == null && positional.size() >= 3 && !"-".equals(positional.get(2))) {
            phase2Path = positional.get(2);
        }
    }

    // ==================== Export Pipeline ====================

    private void exportMeta(Path metaPath, ExportCounts counts) throws Exception {
        LinkedHashMap<String, Object> root = new LinkedHashMap<>();

        String executablePath = currentProgram.getExecutablePath();
        String exeHash = sha256IfReadable(executablePath);

        root.put("schema_version", "factpack-v1");
        root.put("generated_at_utc", Instant.now().toString());
        root.put("program_name", currentProgram.getName());
        root.put("executable_path", executablePath);
        root.put("executable_sha256", exeHash);
        root.put("language_id", currentProgram.getLanguageID().getIdAsString());
        root.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        root.put("image_base", formatAddr(currentProgram.getImageBase().getOffset()));

        root.put("seed_map_path", seedMapPath);
        root.put("allow_ranges_count", allowRanges.size());
        root.put("deny_ranges_count", denyRanges.size());
        root.put("curated_seed_count", curatedSeeds.size());

        List<Object> allow = new ArrayList<>();
        for (AddressRange r : allowRanges) {
            LinkedHashMap<String, Object> m = new LinkedHashMap<>();
            m.put("start", formatAddr(r.start));
            m.put("end", formatAddr(r.end));
            m.put("label", r.label);
            allow.add(m);
        }
        root.put("allow_ranges", allow);

        List<Object> deny = new ArrayList<>();
        for (AddressRange r : denyRanges) {
            LinkedHashMap<String, Object> m = new LinkedHashMap<>();
            m.put("start", formatAddr(r.start));
            m.put("end", formatAddr(r.end));
            m.put("label", r.label);
            deny.add(m);
        }
        root.put("deny_ranges", deny);

        List<Object> embedded = new ArrayList<>();
        for (long[] o : embeddedObjects) {
            LinkedHashMap<String, Object> m = new LinkedHashMap<>();
            m.put("start", formatAddr(o[0]));
            m.put("end", formatAddr(o[1]));
            m.put("size", o[1] - o[0] + 1);
            embedded.add(m);
        }
        root.put("embedded_non_i860_objects", embedded);

        int functionCount = 0;
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) {
            fi.next();
            functionCount++;
        }

        LinkedHashMap<String, Object> countMap = new LinkedHashMap<>();
        countMap.put("functions", counts.functions);
        countMap.put("blocks", counts.blocks);
        countMap.put("edges", counts.edges);
        countMap.put("insns", counts.insns);
        countMap.put("refs", counts.refs);
        countMap.put("strings", counts.strings);
        countMap.put("dispatch_unresolved", counts.dispatchUnresolved);
        countMap.put("code_bytes", counts.codeBytes);
        countMap.put("function_table_count", functionCount);
        root.put("counts", countMap);

        Files.writeString(metaPath, toJson(root) + "\n", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private void exportStrings(Path output, ExportCounts counts) throws Exception {
        try (BufferedWriter w = Files.newBufferedWriter(output, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            DataIterator di = listing.getDefinedData(true);
            while (di.hasNext()) {
                Data d = di.next();
                Object value = d.getValue();
                if (!(value instanceof String)) continue;

                String s = (String) value;
                if (s == null || s.isEmpty()) continue;

                long addr = d.getAddress().getOffset();
                int len = d.getLength();
                String trimmed = trimForJson(s, 512);

                StringRecord rec = new StringRecord(addr, len, trimmed);
                stringRecords.put(addr, rec);

                LinkedHashMap<String, Object> row = new LinkedHashMap<>();
                row.put("addr", formatAddr(addr));
                row.put("length", len);
                row.put("value", trimmed);
                row.put("in_exec", isInExecRange(addr));
                row.put("in_allow", isInAllowedRanges(addr));
                row.put("in_deny", isInDeniedRanges(addr));

                w.write(toJson(row));
                w.write("\n");
                counts.strings++;
            }
        }
    }

    private void exportFunctions(Path output, ExportCounts counts) throws Exception {
        try (BufferedWriter w = Files.newBufferedWriter(output, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            FunctionIterator fi = listing.getFunctions(true);
            while (fi.hasNext()) {
                Function f = fi.next();
                Address entry = f.getEntryPoint();
                long entryOff = entry.getOffset();

                boolean hasUnresolved = functionHasUnresolvedDispatch(f);
                String confidenceSource = inferFunctionConfidenceSource(f, entryOff);

                LinkedHashMap<String, Object> row = new LinkedHashMap<>();
                row.put("entry", formatAddr(entryOff));
                row.put("name", f.getName());
                row.put("size", f.getBody().getNumAddresses());
                row.put("in_exec", isInExecRange(entryOff));
                row.put("in_allow", isInAllowedRanges(entryOff));
                row.put("in_deny", isInDeniedRanges(entryOff));
                row.put("confidence_source", confidenceSource);
                row.put("has_unresolved_bri", hasUnresolved);

                w.write(toJson(row));
                w.write("\n");
                counts.functions++;
            }
        }
    }

    private void exportBlocks(Path output, ExportCounts counts) throws Exception {
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);

        try (BufferedWriter w = Files.newBufferedWriter(output, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            CodeBlockIterator it = bbm.getCodeBlocks(monitor);
            while (it.hasNext()) {
                CodeBlock b = it.next();

                Address start = b.getFirstStartAddress();
                Address end = b.getMaxAddress();
                if (start == null || end == null) continue;

                long startOff = start.getOffset();
                if (!isInExecRange(startOff)) continue;

                Function f = listing.getFunctionContaining(start);
                String funcEntry = (f == null) ? null : formatAddr(f.getEntryPoint().getOffset());

                int insnCount = 0;
                InstructionIterator ii = listing.getInstructions(new AddressSet(start, end), true);
                while (ii.hasNext()) {
                    ii.next();
                    insnCount++;
                }

                LinkedHashMap<String, Object> row = new LinkedHashMap<>();
                row.put("func_entry", funcEntry);
                row.put("block_start", formatAddr(startOff));
                row.put("block_end", formatAddr(end.getOffset()));
                row.put("insn_count", insnCount);

                w.write(toJson(row));
                w.write("\n");
                counts.blocks++;
            }
        }
    }

    private void exportInsnsEdgesRefsDispatch(
        Path insnsPath,
        Path edgesPath,
        Path refsPath,
        Path dispatchPath,
        ExportCounts counts
    ) throws Exception {
        ReferenceManager rm = currentProgram.getReferenceManager();

        try (BufferedWriter insnW = Files.newBufferedWriter(insnsPath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
             BufferedWriter edgeW = Files.newBufferedWriter(edgesPath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
             BufferedWriter refW = Files.newBufferedWriter(refsPath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
             BufferedWriter dispW = Files.newBufferedWriter(dispatchPath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {

            InstructionIterator ii = listing.getInstructions(true);
            while (ii.hasNext()) {
                Instruction insn = ii.next();
                Address addr = insn.getAddress();
                long off = addr.getOffset();
                if (!isInExecRange(off)) continue;

                int word = readWordLE(addr);
                String mnem = insn.getMnemonicString();
                boolean delayed = isDelayedOpcode(word);

                Function f = listing.getFunctionContaining(addr);
                String funcEntry = (f == null) ? null : formatAddr(f.getEntryPoint().getOffset());

                // -------- insns.jsonl --------
                LinkedHashMap<String, Object> row = new LinkedHashMap<>();
                row.put("addr", formatAddr(off));
                row.put("func_entry", funcEntry);
                row.put("word", formatWord(word));
                row.put("mnemonic", mnem);
                row.put("operands", insn.toString());
                row.put("defs", toObjectStrings(insn.getResultObjects()));
                row.put("uses", toObjectStrings(insn.getInputObjects()));
                row.put("pcode_ops", pcodeOps(insn));
                row.put("flows", flowTargets(insn));
                row.put("mmio_tag", detectMmioTag(insn));

                StringRefHit hit = firstStringRefHit(insn, rm);
                if (hit != null) {
                    LinkedHashMap<String, Object> sref = new LinkedHashMap<>();
                    sref.put("addr", formatAddr(hit.addr));
                    sref.put("value", trimForJson(hit.value, 128));
                    row.put("string_ref", sref);
                }
                else {
                    row.put("string_ref", null);
                }

                insnW.write(toJson(row));
                insnW.write("\n");
                counts.insns++;
                counts.codeBytes += insn.getLength();

                // -------- refs.jsonl --------
                Reference[] refs = rm.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    Address to = ref.getToAddress();
                    if (to == null) continue;

                    LinkedHashMap<String, Object> rr = new LinkedHashMap<>();
                    rr.put("from", formatAddr(off));
                    rr.put("to", formatAddr(to.getOffset()));
                    rr.put("type", ref.getReferenceType().toString());
                    rr.put("is_flow", ref.getReferenceType().isFlow());
                    rr.put("is_primary", ref.isPrimary());

                    refW.write(toJson(rr));
                    refW.write("\n");
                    counts.refs++;
                }

                // -------- edges.jsonl --------
                FlowType ft = insn.getFlowType();
                Address[] flows = insn.getFlows();

                if (flows != null && flows.length > 0) {
                    for (Address t : flows) {
                        LinkedHashMap<String, Object> er = new LinkedHashMap<>();
                        er.put("src", formatAddr(off));
                        er.put("dst", formatAddr(t.getOffset()));
                        er.put("kind", classifyEdgeKind(ft, mnem));
                        er.put("delay_slot", delayed);

                        edgeW.write(toJson(er));
                        edgeW.write("\n");
                        counts.edges++;
                    }
                }
                else if (ft != null && (ft.isCall() || ft.isJump()) && ft.isComputed()) {
                    LinkedHashMap<String, Object> er = new LinkedHashMap<>();
                    er.put("src", formatAddr(off));
                    er.put("dst", null);
                    er.put("kind", classifyEdgeKind(ft, mnem));
                    er.put("delay_slot", delayed);

                    edgeW.write(toJson(er));
                    edgeW.write("\n");
                    counts.edges++;
                }

                Address fall = insn.getFallThrough();
                if (fall != null && isInExecRange(fall.getOffset())) {
                    LinkedHashMap<String, Object> fr = new LinkedHashMap<>();
                    fr.put("src", formatAddr(off));
                    fr.put("dst", formatAddr(fall.getOffset()));
                    fr.put("kind", "fallthrough");
                    fr.put("delay_slot", false);

                    edgeW.write(toJson(fr));
                    edgeW.write("\n");
                    counts.edges++;
                }

                // -------- dispatch_unresolved.jsonl --------
                boolean unresolvedDispatch = isUnresolvedDispatch(insn);
                if (unresolvedDispatch) {
                    LinkedHashMap<String, Object> dr = new LinkedHashMap<>();
                    dr.put("addr", formatAddr(off));
                    dr.put("func_entry", funcEntry);
                    dr.put("mnemonic", mnem);
                    dr.put("flow_type", ft == null ? null : ft.toString());

                    String phase2Class = phase2DispatchClassByAddr.get(formatAddr(off).toLowerCase());
                    dr.put("phase2_classification", phase2Class);

                    dispW.write(toJson(dr));
                    dispW.write("\n");
                    counts.dispatchUnresolved++;
                }
            }
        }
    }

    // ==================== Dispatch / Intent Helpers ====================

    private boolean isUnresolvedDispatch(Instruction insn) {
        FlowType ft = insn.getFlowType();
        String m = insn.getMnemonicString();

        if ("bri".equalsIgnoreCase(m) || "calli".equalsIgnoreCase(m)) return true;

        if (ft != null && (ft.isJump() || ft.isCall()) && ft.isComputed()) {
            Address[] flows = insn.getFlows();
            return flows == null || flows.length == 0;
        }
        return false;
    }

    private boolean functionHasUnresolvedDispatch(Function f) {
        InstructionIterator ii = listing.getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            Instruction insn = ii.next();
            if (isUnresolvedDispatch(insn)) return true;
        }
        return false;
    }

    private String inferFunctionConfidenceSource(Function f, long entryOff) {
        if (curatedSeeds.contains(entryOff)) return "curated";
        if (entryOff == currentProgram.getImageBase().getOffset()) return "entry";

        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(f.getEntryPoint());
        if (sym != null && sym.getSource() != null) {
            return sym.getSource().toString().toLowerCase();
        }
        return "analysis";
    }

    private static class StringRefHit {
        final long addr;
        final String value;

        StringRefHit(long addr, String value) {
            this.addr = addr;
            this.value = value;
        }
    }

    private StringRefHit firstStringRefHit(Instruction insn, ReferenceManager rm) {
        Reference[] refs = rm.getReferencesFrom(insn.getAddress());
        for (Reference ref : refs) {
            Address to = ref.getToAddress();
            if (to == null) continue;
            long toOff = to.getOffset();

            Map.Entry<Long, StringRecord> floor = ((TreeMap<Long, StringRecord>) stringRecords).floorEntry(toOff);
            if (floor == null) continue;
            StringRecord sr = floor.getValue();
            if (toOff >= sr.addr && toOff < sr.addr + sr.length) {
                return new StringRefHit(sr.addr, sr.value);
            }
        }
        return null;
    }

    private String detectMmioTag(Instruction insn) {
        Set<String> tags = new LinkedHashSet<>();

        int nops = insn.getNumOperands();
        for (int i = 0; i < nops; i++) {
            Object[] objs = insn.getOpObjects(i);
            boolean hasR0 = false;

            for (Object o : objs) {
                if (o instanceof Register) {
                    String rn = ((Register) o).getName();
                    if ("r0".equalsIgnoreCase(rn)) {
                        hasR0 = true;
                    }
                }
            }

            for (Object o : objs) {
                if (o instanceof Scalar) {
                    Scalar s = (Scalar) o;
                    long unsigned = s.getUnsignedValue() & U32_MASK;
                    long signedU32 = s.getSignedValue() & U32_MASK;

                    // Literal displacements are unresolved without a base register value.
                    if (unsigned == 0x401cL) {
                        if (hasR0) tags.add("mmio_abs_0000401c_r0");
                        else tags.add("mmio_offset_0x401c_unresolved");
                    }
                    if (unsigned == 0x401eL) {
                        if (hasR0) tags.add("mmio_abs_0000401e_r0");
                        else tags.add("mmio_offset_0x401e_unresolved");
                    }

                    // Absolute immediates (e.g. orh/or constants).
                    addAbsoluteMmioTags(tags, unsigned);

                    // r0-base addressing computes absolute effective addresses.
                    if (hasR0) {
                        addAbsoluteMmioTags(tags, signedU32);
                    }
                }
                else if (o instanceof Address) {
                    addAbsoluteMmioTags(tags, ((Address) o).getOffset());
                }
            }
        }

        if (tags.isEmpty()) return null;
        return String.join(",", tags);
    }

    private void addAbsoluteMmioTags(Set<String> tags, long rawAddr) {
        long addr = rawAddr & U32_MASK;
        if (addr >= I860_MMIO_BASE && addr <= I860_MMIO_END) tags.add("mmio_abs_i860_0200xxxx");
        if (addr >= HOST_IO_BASE && addr <= HOST_IO_END) tags.add("mmio_abs_host_ff800xxx");
        if (addr >= DP_BASE && addr <= DP_END) tags.add("mmio_abs_dp_f000xxxx");
        if (addr == 0x0000401cL) tags.add("mmio_abs_0000401c");
        if (addr == 0x0000401eL) tags.add("mmio_abs_0000401e");
    }

    private String classifyEdgeKind(FlowType ft, String mnemonic) {
        if (ft == null) return "flow";
        if (ft.isCall()) {
            return ft.isComputed() ? "call_indirect" : "call";
        }
        if (ft.isJump()) {
            if (ft.isComputed()) return "indirect";
            if (ft.isConditional()) return "branch_cond";
            return "branch";
        }
        if (ft.isTerminal()) {
            if (mnemonic != null && mnemonic.toLowerCase().contains("trap")) return "trap";
            return "return";
        }
        return "flow";
    }

    private List<Object> flowTargets(Instruction insn) {
        List<Object> out = new ArrayList<>();
        Address[] flows = insn.getFlows();
        if (flows != null) {
            for (Address a : flows) {
                out.add(formatAddr(a.getOffset()));
            }
        }
        return out;
    }

    private List<Object> pcodeOps(Instruction insn) {
        LinkedHashSet<String> ops = new LinkedHashSet<>();
        try {
            PcodeOp[] p = insn.getPcode();
            if (p != null) {
                for (PcodeOp op : p) {
                    if (op == null) continue;
                    ops.add(PcodeOp.getMnemonic(op.getOpcode()));
                }
            }
        } catch (Exception e) {
            // ignore pcode extraction failures
        }
        return new ArrayList<>(ops);
    }

    private List<Object> toObjectStrings(Object[] objs) {
        List<Object> out = new ArrayList<>();
        if (objs == null) return out;
        for (Object o : objs) {
            if (o == null) continue;
            if (o instanceof Register) {
                out.add(((Register) o).getName());
            }
            else if (o instanceof Scalar) {
                out.add("0x" + Long.toHexString(((Scalar) o).getUnsignedValue()));
            }
            else if (o instanceof Address) {
                out.add(formatAddr(((Address) o).getOffset()));
            }
            else {
                out.add(o.toString());
            }
        }
        return out;
    }

    // ==================== Seed Map + Phase2 ====================

    private void loadSeedMap() {
        allowRanges.clear();
        denyRanges.clear();
        curatedSeeds.clear();
        if (seedMapPath == null) return;

        try {
            String json = Files.readString(Paths.get(seedMapPath));
            allowRanges = parseRangeArray(json, "allow_ranges", "allow");
            denyRanges = parseRangeArray(json, "deny_ranges", "deny");
            curatedSeeds = parseSeedSet(json, "seeds");
        }
        catch (Exception e) {
            printerr("Failed to read seed map: " + seedMapPath + " (" + e.getMessage() + ")");
            allowRanges.clear();
            denyRanges.clear();
            curatedSeeds.clear();
        }
    }

    private void loadPhase2Hints() {
        phase2DispatchClassByAddr.clear();
        if (phase2Path == null) return;

        Path p = Paths.get(phase2Path);
        if (!Files.exists(p)) return;

        try {
            String pendingAddr = null;
            List<String> lines = Files.readAllLines(p);
            for (String raw : lines) {
                String line = raw.trim();
                if (line.startsWith("\"bri_addr\"")) {
                    String a = parseQuotedValue(line);
                    if (a != null) pendingAddr = a.toLowerCase();
                    continue;
                }
                if (line.startsWith("\"classification\"")) {
                    String c = parseQuotedValue(line);
                    if (c != null && pendingAddr != null) {
                        phase2DispatchClassByAddr.put(pendingAddr, c);
                    }
                    continue;
                }
                if (line.startsWith("},") || line.equals("}")) {
                    pendingAddr = null;
                }
            }
        }
        catch (Exception e) {
            printerr("Failed to parse phase2 hints: " + phase2Path + " (" + e.getMessage() + ")");
        }
    }

    private static String parseQuotedValue(String line) {
        Matcher m = Pattern.compile("\\\"[^\\\"]+\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"").matcher(line);
        return m.find() ? m.group(1) : null;
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

    private Set<Long> parseSeedSet(String json, String key) {
        Set<Long> seeds = new HashSet<>();
        String body = extractArrayBody(json, key);
        if (body == null) return seeds;

        Matcher objectMatcher = Pattern.compile("\\{(.*?)\\}", Pattern.DOTALL).matcher(body);
        while (objectMatcher.find()) {
            String obj = objectMatcher.group(1);
            Long addr = parseAddressField(obj, "addr");
            if (addr == null) addr = parseAddressField(obj, "address");
            if (addr != null) seeds.add(addr);
        }
        return seeds;
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
        }
        catch (Exception e) {
            return null;
        }
    }

    // ==================== Exec Range / Embedded Objects ====================

    private void buildExecRanges() {
        execRanges.clear();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;
            execRanges.add(new long[] { block.getStart().getOffset(), block.getEnd().getOffset() });
        }
    }

    private List<long[]> detectEmbeddedObjects() throws Exception {
        List<long[]> objects = new ArrayList<>();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long startOff = block.getStart().getOffset();
            long endOff = block.getEnd().getOffset();
            long blockSize = endOff - startOff + 1;
            if (blockSize > Integer.MAX_VALUE) continue;

            byte[] bytes = new byte[(int) blockSize];
            block.getBytes(block.getStart(), bytes);

            List<long[]> magics = new ArrayList<>();
            for (int i = 0; i < bytes.length - 28; i += 4) {
                int wordBE = ((bytes[i] & 0xff) << 24) | ((bytes[i + 1] & 0xff) << 16) |
                             ((bytes[i + 2] & 0xff) << 8) | (bytes[i + 3] & 0xff);

                boolean isBE = (wordBE == 0xFEEDFACE);
                boolean isLE = (wordBE == 0xCEFAEDFE);
                if (!isBE && !isLE) continue;

                long addr = startOff + i;
                int cpuType;
                if (isBE) {
                    cpuType = ((bytes[i + 4] & 0xff) << 24) | ((bytes[i + 5] & 0xff) << 16) |
                              ((bytes[i + 6] & 0xff) << 8) | (bytes[i + 7] & 0xff);
                }
                else {
                    cpuType = (bytes[i + 4] & 0xff) | ((bytes[i + 5] & 0xff) << 8) |
                              ((bytes[i + 6] & 0xff) << 16) | ((bytes[i + 7] & 0xff) << 24);
                }
                magics.add(new long[] { addr, cpuType });
            }

            for (int m = 0; m < magics.size(); m++) {
                long addr = magics.get(m)[0];
                int cpuType = (int) magics.get(m)[1];

                if (addr == startOff) continue;
                if (cpuType == 15) continue; // i860

                int base = (int) (addr - startOff);
                int w = ((bytes[base] & 0xff) << 24) | ((bytes[base + 1] & 0xff) << 16) |
                        ((bytes[base + 2] & 0xff) << 8) | (bytes[base + 3] & 0xff);
                boolean objBE = (w == 0xFEEDFACE);

                int ncmds = readMachInt(bytes, base + 16, objBE);
                int sizeOfCmds = readMachInt(bytes, base + 20, objBE);

                long maxFileEnd = 28L + sizeOfCmds;
                int cmdOff = base + 28;
                for (int c = 0; c < ncmds && cmdOff + 8 <= bytes.length; c++) {
                    int cmd = readMachInt(bytes, cmdOff, objBE);
                    int cmdSize = readMachInt(bytes, cmdOff + 4, objBE);
                    if (cmdSize < 8) break;
                    if (cmd == 1 && cmdOff + 40 <= bytes.length) {
                        int fileOff = readMachInt(bytes, cmdOff + 32, objBE);
                        int fileSize = readMachInt(bytes, cmdOff + 36, objBE);
                        long segEnd = (long) fileOff + fileSize;
                        if (segEnd > maxFileEnd) maxFileEnd = segEnd;
                    }
                    cmdOff += cmdSize;
                }

                long objEnd = Math.min(addr + maxFileEnd - 1, endOff);
                objects.add(new long[] { addr, objEnd });
            }
        }

        if (objects.size() <= 1) return objects;

        objects.sort((a, b) -> Long.compare(a[0], b[0]));
        List<long[]> merged = new ArrayList<>();
        long[] current = objects.get(0);
        for (int i = 1; i < objects.size(); i++) {
            long[] next = objects.get(i);
            if (next[0] <= current[1] + 1) {
                current[1] = Math.max(current[1], next[1]);
            }
            else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        return merged;
    }

    private static int readMachInt(byte[] data, int offset, boolean be) {
        if (be) {
            return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16) |
                   ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
        }
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8) |
               ((data[offset + 2] & 0xff) << 16) | ((data[offset + 3] & 0xff) << 24);
    }

    private int readWordLE(Address addr) {
        try {
            return memory.getInt(addr);
        }
        catch (Exception e) {
            return 0;
        }
    }

    // Delayed ops in local i860 model: br/call/bc.t/bnc.t/bla/bri/calli
    private boolean isDelayedOpcode(int word) {
        int op6 = (word >>> 26) & 0x3f;
        if (op6 == 0x1a || op6 == 0x1b || op6 == 0x1d || op6 == 0x1f || op6 == 0x2d || op6 == 0x10) {
            return true;
        }
        if (op6 == 0x13) {
            int escop = word & 0x7;
            return escop == 0x2; // calli
        }
        return false;
    }

    private boolean isInExecRange(long addr) {
        for (long[] r : execRanges) {
            if (addr >= r[0] && addr <= r[1]) return true;
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

    // ==================== JSON Helpers ====================

    private static String formatAddr(long v) {
        return String.format("0x%08x", v);
    }

    private static String formatWord(int w) {
        long u = w & 0xffffffffL;
        return String.format("0x%08x", u);
    }

    private static String trimForJson(String s, int max) {
        if (s == null) return null;
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    private static String sha256IfReadable(String executablePath) {
        if (executablePath == null) return null;

        String p = executablePath;
        if (p.startsWith("file://")) {
            p = p.substring("file://".length());
        }

        try {
            Path path = Paths.get(p);
            if (!Files.exists(path) || !Files.isRegularFile(path)) return null;

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] data = Files.readAllBytes(path);
            byte[] hash = md.digest(data);
            return String.format("%064x", new BigInteger(1, hash));
        }
        catch (Exception e) {
            return null;
        }
    }

    private static String toJson(Object obj) {
        if (obj == null) return "null";

        if (obj instanceof String) return quoteJson((String) obj);
        if (obj instanceof Number || obj instanceof Boolean) return String.valueOf(obj);

        if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> m = (Map<Object, Object>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            boolean first = true;
            for (Map.Entry<Object, Object> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(quoteJson(String.valueOf(e.getKey())));
                sb.append(':');
                sb.append(toJson(e.getValue()));
            }
            sb.append('}');
            return sb.toString();
        }

        if (obj instanceof Iterable) {
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            boolean first = true;
            for (Object it : (Iterable<?>) obj) {
                if (!first) sb.append(',');
                first = false;
                sb.append(toJson(it));
            }
            sb.append(']');
            return sb.toString();
        }

        if (obj.getClass().isArray()) {
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            int len = java.lang.reflect.Array.getLength(obj);
            for (int i = 0; i < len; i++) {
                if (i > 0) sb.append(',');
                sb.append(toJson(java.lang.reflect.Array.get(obj, i)));
            }
            sb.append(']');
            return sb.toString();
        }

        return quoteJson(String.valueOf(obj));
    }

    private static String quoteJson(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
