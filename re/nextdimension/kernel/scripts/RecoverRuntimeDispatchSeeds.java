// Recover probable runtime-generated dispatch targets from initialization stores.
//
// Strategy:
//   1) Track simple per-function register constants (focused on orh+or address construction).
//   2) Detect stores of executable pointers into writable runtime memory.
//   3) Emit recovery-map JSON compatible with I860Analyze.java (seeds array).
//
// Script args (optional):
//   arg0: output recovery JSON path (default: /tmp/i860_runtime_recovery.json)
//   arg1: output text report path  (default: /tmp/i860_runtime_targets.txt)
//   arg2: min score for create_function=true (default: 75)
//   arg3: min score for include as decode-only seed (default: 65)
//   arg4: optional hint-range start (hex, e.g. 0xF80B7C00)
//   arg5: optional hint-range end   (hex, e.g. 0xF80C4097)
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

public class RecoverRuntimeDispatchSeeds extends GhidraScript {

    private static final long U32_MASK = 0xFFFFFFFFL;
    private static final int DEFAULT_CREATE_SCORE = 75;
    private static final int DEFAULT_DECODE_SCORE = 65;

    private Listing listing;
    private Memory memory;
    private AddressSpace space;

    private String outJsonPath = "/tmp/i860_runtime_recovery.json";
    private String outTextPath = "/tmp/i860_runtime_targets.txt";
    private int minCreateScore = DEFAULT_CREATE_SCORE;
    private int minDecodeScore = DEFAULT_DECODE_SCORE;

    private final List<long[]> execRanges = new ArrayList<>();
    private final List<long[]> runtimeWriteRanges = new ArrayList<>();
    private final List<long[]> hintRanges = new ArrayList<>();

    private final Map<Long, SeedInfo> seedsByTarget = new LinkedHashMap<>();

    private static class ConstVal {
        final long value;
        final String kind;
        final Address definedAt;

        ConstVal(long value, String kind, Address definedAt) {
            this.value = value & U32_MASK;
            this.kind = kind;
            this.definedAt = definedAt;
        }
    }

    private static class SeedInfo {
        final long target;
        int writes = 0;
        int maxScore = Integer.MIN_VALUE;
        int minScore = Integer.MAX_VALUE;
        final TreeSet<Long> destAddrs = new TreeSet<>();
        final TreeSet<String> functions = new TreeSet<>();
        final List<String> evidence = new ArrayList<>();

        SeedInfo(long target) {
            this.target = target & U32_MASK;
        }
    }

    private static class SeedCandidate {
        final SeedInfo info;
        final boolean createFunction;

        SeedCandidate(SeedInfo info, boolean createFunction) {
            this.info = info;
            this.createFunction = createFunction;
        }
    }

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        parseArgs(getScriptArgs());
        collectRanges();

        printf("=== RecoverRuntimeDispatchSeeds ===%n");
        printf("Program:              %s%n", currentProgram.getName());
        printf("Exec ranges:          %d%n", execRanges.size());
        printf("Writable non-exec:    %d%n", runtimeWriteRanges.size());
        printf("Hint ranges:          %d%n", hintRanges.size());

        int funcs = 0;
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = fi.next();
            if (f == null) continue;
            funcs++;
            analyzeFunction(f);
        }

        List<SeedInfo> infos = new ArrayList<>(seedsByTarget.values());
        infos.sort(
            Comparator
                .comparingInt((SeedInfo s) -> s.maxScore).reversed()
                .thenComparingInt((SeedInfo s) -> s.writes).reversed()
                .thenComparingLong((SeedInfo s) -> s.target)
        );

        List<SeedCandidate> selected = selectSeeds(infos);
        writeTextReport(infos, selected, funcs);
        writeRecoveryJson(selected);

        int createCount = 0;
        int decodeOnlyCount = 0;
        for (SeedCandidate c : selected) {
            if (c.createFunction) createCount++;
            else decodeOnlyCount++;
        }

        printf("Functions scanned:    %d%n", funcs);
        printf("Targets recovered:    %d%n", infos.size());
        printf("Seeds emitted:        %d (create=%d decode-only=%d)%n",
            selected.size(), createCount, decodeOnlyCount);
        printf("Output JSON:          %s%n", outJsonPath);
        printf("Output report:        %s%n", outTextPath);
    }

    private void parseArgs(String[] args) {
        if (args == null) return;
        if (args.length >= 1 && !args[0].trim().isEmpty()) outJsonPath = args[0].trim();
        if (args.length >= 2 && !args[1].trim().isEmpty()) outTextPath = args[1].trim();
        if (args.length >= 3) minCreateScore = parseInt(args[2], DEFAULT_CREATE_SCORE);
        if (args.length >= 4) minDecodeScore = parseInt(args[3], DEFAULT_DECODE_SCORE);

        if (args.length >= 6) {
            Long start = parseAddress(args[4]);
            Long end = parseAddress(args[5]);
            if (start != null && end != null) {
                hintRanges.add(normalizeRange(start.longValue(), end.longValue()));
            }
        }
    }

    private void collectRanges() {
        for (MemoryBlock b : memory.getBlocks()) {
            long start = b.getStart().getOffset() & U32_MASK;
            long end = b.getEnd().getOffset() & U32_MASK;
            if (b.isExecute()) {
                execRanges.add(new long[] { start, end });
            }
            if (b.isWrite() && !b.isExecute()) {
                runtimeWriteRanges.add(new long[] { start, end });
            }
        }

        // Known ND firmware runtime data zone (used when available in the loaded memory map).
        hintRanges.add(normalizeRange(0xF80B7C00L, 0xF80C4097L));

        coalesceRanges(execRanges);
        coalesceRanges(runtimeWriteRanges);
        coalesceRanges(hintRanges);
    }

    private void analyzeFunction(Function f) {
        Map<String, ConstVal> regs = new HashMap<>();
        regs.put("r0", new ConstVal(0L, "r0", null));

        InstructionIterator ii = listing.getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction ins = ii.next();
            String m = normalizeMnemonic(ins.getMnemonicString());

            if (isStoreMnemonic(m)) {
                processStore(ins, m, regs, f);
            }

            boolean handled = propagate(ins, m, regs);
            if (!handled) {
                killWrittenRegisters(ins, regs);
            }

            if (isCallMnemonic(m)) {
                // Calls break local constant assumptions.
                regs.clear();
            }
            regs.put("r0", new ConstVal(0L, "r0", null));
        }
    }

    private boolean propagate(Instruction ins, String m, Map<String, ConstVal> regs) {
        if ("mov".equals(m)) {
            Register src = getFirstRegister(ins, 0);
            Register dst = getFirstRegister(ins, 1);
            if (src == null || dst == null) return false;
            ConstVal v = readConst(src, regs);
            if (v == null) {
                regs.remove(norm(dst));
            } else {
                regs.put(norm(dst), new ConstVal(v.value, "mov:" + v.kind, ins.getAddress()));
            }
            return true;
        }

        if (Arrays.asList("orh", "or", "addu", "adds", "subu", "subs", "xorh", "andh").contains(m)) {
            Scalar imm = getFirstScalar(ins, 0);
            Register src = getFirstRegister(ins, 1);
            Register dst = getFirstRegister(ins, 2);
            if (imm == null || src == null || dst == null) return false;

            ConstVal sv = readConst(src, regs);
            if (sv == null) {
                regs.remove(norm(dst));
                return true;
            }

            long immU = imm.getUnsignedValue() & 0xFFFFL;
            long immS = signExtend16(immU);
            long out;
            String kind = m;

            if ("orh".equals(m)) {
                out = (sv.value | ((immU << 16) & U32_MASK)) & U32_MASK;
                kind = "orh";
            } else if ("or".equals(m)) {
                out = (sv.value | immU) & U32_MASK;
                if ("orh".equals(sv.kind) || sv.kind.startsWith("orh:")) {
                    kind = "orh_or";
                } else {
                    kind = "or_imm:" + sv.kind;
                }
            } else if ("addu".equals(m) || "adds".equals(m)) {
                out = (sv.value + immS) & U32_MASK;
                kind = "add_imm:" + sv.kind;
            } else if ("subu".equals(m) || "subs".equals(m)) {
                out = (sv.value - immS) & U32_MASK;
                kind = "sub_imm:" + sv.kind;
            } else if ("xorh".equals(m)) {
                out = (sv.value ^ ((immU << 16) & U32_MASK)) & U32_MASK;
                kind = "xorh:" + sv.kind;
            } else if ("andh".equals(m)) {
                out = (sv.value & ((immU << 16) & U32_MASK)) & U32_MASK;
                kind = "andh:" + sv.kind;
            } else {
                return false;
            }

            regs.put(norm(dst), new ConstVal(out, kind, ins.getAddress()));
            return true;
        }

        if ("or".equals(m)) {
            // Register-register OR form.
            Register a = getFirstRegister(ins, 0);
            Register b = getFirstRegister(ins, 1);
            Register d = getFirstRegister(ins, 2);
            if (a == null || b == null || d == null) return false;
            ConstVal av = readConst(a, regs);
            ConstVal bv = readConst(b, regs);
            if (av == null || bv == null) {
                regs.remove(norm(d));
            } else {
                long out = (av.value | bv.value) & U32_MASK;
                regs.put(norm(d), new ConstVal(out, "or_reg", ins.getAddress()));
            }
            return true;
        }

        return false;
    }

    private void processStore(Instruction ins, String mnemonic, Map<String, ConstVal> regs, Function f) {
        if ("st.c".equals(mnemonic)) return;
        if (ins.getNumOperands() < 2) return;

        Register srcReg = getFirstRegister(ins, 0);
        if (srcReg == null) return;

        ConstVal src = readConst(srcReg, regs);
        if (src == null) return;

        long value = src.value & U32_MASK;
        if (!isExecPointer(value)) return;

        Long dstAddr = evalAddressOperand(ins, 1, regs);
        if (dstAddr == null) return;
        if (!isRuntimeWriteAddress(dstAddr.longValue())) return;

        int score = scoreHit(mnemonic, src.kind, dstAddr.longValue());
        recordHit(value, dstAddr.longValue(), score, f.getName(), ins.getAddress(), mnemonic, src.kind);
    }

    private int scoreHit(String mnemonic, String srcKind, long dstAddr) {
        int score = 30;

        if ("st.l".equals(mnemonic)) score += 30;
        else if ("st.s".equals(mnemonic)) score += 20;
        else if ("st.b".equals(mnemonic)) score += 6;

        if (srcKind != null) {
            if (srcKind.contains("orh_or")) score += 30;
            else if (srcKind.startsWith("orh")) score += 16;
            else if (srcKind.startsWith("mov:orh")) score += 12;
        }

        if (isInRanges(dstAddr, hintRanges)) score += 10;
        if (isInRanges(dstAddr, runtimeWriteRanges)) score += 8;

        return Math.max(0, Math.min(100, score));
    }

    private void recordHit(long target, long dstAddr, int score, String fn, Address at, String mnemonic, String srcKind) {
        Long key = Long.valueOf(target & U32_MASK);
        SeedInfo s = seedsByTarget.get(key);
        if (s == null) {
            s = new SeedInfo(target);
            seedsByTarget.put(key, s);
        }

        s.writes++;
        s.maxScore = Math.max(s.maxScore, score);
        s.minScore = Math.min(s.minScore, score);
        s.destAddrs.add(Long.valueOf(dstAddr & U32_MASK));
        s.functions.add(fn);

        if (s.evidence.size() < 8) {
            s.evidence.add(String.format(Locale.ROOT,
                "%s %s @%s -> [0x%08X] = 0x%08X (%s, score=%d)",
                fn,
                mnemonic,
                at,
                dstAddr & U32_MASK,
                target & U32_MASK,
                srcKind,
                score
            ));
        }
    }

    private List<SeedCandidate> selectSeeds(List<SeedInfo> infos) {
        List<SeedCandidate> out = new ArrayList<>();

        for (SeedInfo s : infos) {
            boolean create = s.maxScore >= minCreateScore;
            boolean decodeOnly = s.maxScore >= minDecodeScore;
            if (!create && !decodeOnly) continue;
            out.add(new SeedCandidate(s, create));
        }

        // Fallback: if nothing met create threshold, promote strongest decode seeds.
        boolean hasCreate = false;
        for (SeedCandidate c : out) {
            if (c.createFunction) {
                hasCreate = true;
                break;
            }
        }

        if (!hasCreate && !out.isEmpty()) {
            int promote = Math.min(32, out.size());
            for (int i = 0; i < promote; i++) {
                SeedCandidate c = out.get(i);
                out.set(i, new SeedCandidate(c.info, true));
            }
        }

        return out;
    }

    private void writeTextReport(List<SeedInfo> infos, List<SeedCandidate> selected, int funcs) throws Exception {
        File f = new File(outTextPath);
        if (f.getParentFile() != null && !f.getParentFile().exists()) {
            f.getParentFile().mkdirs();
        }

        PrintWriter pw = new PrintWriter(new FileWriter(f));
        pw.println("=== Runtime Dispatch Seed Recovery ===");
        pw.printf("Program: %s%n", currentProgram.getName());
        pw.printf("Functions scanned: %d%n", funcs);
        pw.printf("Targets recovered: %d%n", infos.size());
        pw.printf("Seed thresholds: create>= %d, decode>= %d%n", minCreateScore, minDecodeScore);
        pw.printf("Seeds emitted: %d%n", selected.size());
        pw.println();

        pw.println("Top recovered targets:");
        pw.println("Target       MaxSc  Writes  DestSlots  Functions");
        pw.println("-----------  -----  ------  ---------  ---------");
        int limit = Math.min(150, infos.size());
        for (int i = 0; i < limit; i++) {
            SeedInfo s = infos.get(i);
            pw.printf(Locale.ROOT,
                "0x%08X   %3d    %4d     %4d      %4d%n",
                s.target,
                s.maxScore,
                s.writes,
                s.destAddrs.size(),
                s.functions.size()
            );
        }

        pw.println();
        pw.println("Selected seeds:");
        for (SeedCandidate c : selected) {
            SeedInfo s = c.info;
            pw.printf(Locale.ROOT,
                "0x%08X  create=%s  maxScore=%d  writes=%d%n",
                s.target,
                String.valueOf(c.createFunction),
                s.maxScore,
                s.writes
            );
            int emax = Math.min(3, s.evidence.size());
            for (int i = 0; i < emax; i++) {
                pw.printf("  - %s%n", s.evidence.get(i));
            }
        }

        pw.close();
    }

    private void writeRecoveryJson(List<SeedCandidate> selected) throws Exception {
        File f = new File(outJsonPath);
        if (f.getParentFile() != null && !f.getParentFile().exists()) {
            f.getParentFile().mkdirs();
        }

        StringBuilder sb = new StringBuilder(128 * 1024);
        sb.append("{\n");
        sb.append("  \"meta\": {\n");
        sb.append("    \"name\": \"runtime-dispatch-recovery\",\n");
        sb.append("    \"version\": \"1\",\n");
        sb.append("    \"program\": \"").append(jsonEscape(currentProgram.getName())).append("\",\n");
        sb.append("    \"source\": \"RecoverRuntimeDispatchSeeds.java\",\n");
        sb.append("    \"create_threshold\": ").append(minCreateScore).append(",\n");
        sb.append("    \"decode_threshold\": ").append(minDecodeScore).append(",\n");
        sb.append("    \"seed_count\": ").append(selected.size()).append("\n");
        sb.append("  },\n");
        sb.append("  \"allow_ranges\": [],\n");
        sb.append("  \"deny_ranges\": [],\n");
        sb.append("  \"seeds\": [\n");

        for (int i = 0; i < selected.size(); i++) {
            SeedCandidate c = selected.get(i);
            SeedInfo s = c.info;
            sb.append("    {\"addr\": \"").append(hex32(s.target)).append("\", ");
            sb.append("\"name\": \"runtime_0x").append(String.format(Locale.ROOT, "%08X", s.target)).append("\", ");
            sb.append("\"create_function\": ").append(c.createFunction);
            sb.append(", \"score\": ").append(s.maxScore);
            sb.append(", \"writes\": ").append(s.writes);
            sb.append("}");
            if (i + 1 < selected.size()) sb.append(",");
            sb.append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");

        PrintWriter pw = new PrintWriter(new FileWriter(f));
        pw.print(sb.toString());
        pw.close();
    }

    private ConstVal readConst(Register r, Map<String, ConstVal> regs) {
        if (r == null) return null;
        String n = norm(r);
        if ("r0".equals(n)) return new ConstVal(0L, "r0", null);
        return regs.get(n);
    }

    private Long evalAddressOperand(Instruction ins, int opIndex, Map<String, ConstVal> regs) {
        Object[] objs = ins.getOpObjects(opIndex);
        if (objs == null || objs.length == 0) return null;

        Address abs = null;
        Long base = null;
        long disp = 0;

        for (Object o : objs) {
            if (o instanceof Address) {
                abs = (Address) o;
            } else if (o instanceof Scalar) {
                disp += ((Scalar) o).getSignedValue();
            } else if (o instanceof Register) {
                ConstVal cv = readConst((Register) o, regs);
                if (cv == null) return null;
                if (base == null) base = Long.valueOf(cv.value);
                else base = Long.valueOf((base.longValue() + cv.value) & U32_MASK);
            }
        }

        if (abs != null) {
            return Long.valueOf(abs.getOffset() & U32_MASK);
        }
        if (base == null) return null;
        return Long.valueOf((base.longValue() + disp) & U32_MASK);
    }

    private boolean isStoreMnemonic(String m) {
        if (m == null) return false;
        if (!m.startsWith("st")) return false;
        return !"st.c".equals(m);
    }

    private boolean isCallMnemonic(String m) {
        if (m == null) return false;
        return "call".equals(m) || "calli".equals(m);
    }

    private boolean isExecPointer(long value) {
        long v = value & U32_MASK;
        if ((v & 3L) != 0) return false;
        return isInRanges(v, execRanges);
    }

    private boolean isRuntimeWriteAddress(long addr) {
        long a = addr & U32_MASK;
        Address aa = toAddress(a);
        if (aa == null || !memory.contains(aa)) return false;

        if (isInRanges(a, runtimeWriteRanges)) return true;
        return isInRanges(a, hintRanges);
    }

    private Address toAddress(long off) {
        try {
            return space.getAddress(off & U32_MASK);
        } catch (Exception e) {
            return null;
        }
    }

    private void killWrittenRegisters(Instruction ins, Map<String, ConstVal> regs) {
        Object[] results = ins.getResultObjects();
        if (results == null) return;
        for (Object o : results) {
            if (o instanceof Register) {
                String n = norm((Register) o);
                if (!"r0".equals(n)) regs.remove(n);
            }
        }
    }

    private Register getFirstRegister(Instruction ins, int opIndex) {
        if (opIndex < 0 || opIndex >= ins.getNumOperands()) return null;
        Object[] objs = ins.getOpObjects(opIndex);
        if (objs == null) return null;
        for (Object o : objs) {
            if (o instanceof Register) return (Register) o;
        }
        return null;
    }

    private Scalar getFirstScalar(Instruction ins, int opIndex) {
        if (opIndex < 0 || opIndex >= ins.getNumOperands()) return null;
        Object[] objs = ins.getOpObjects(opIndex);
        if (objs == null) return null;
        for (Object o : objs) {
            if (o instanceof Scalar) return (Scalar) o;
        }
        return null;
    }

    private static String normalizeMnemonic(String s) {
        if (s == null) return "";
        String v = s.trim().toLowerCase(Locale.ROOT);
        while (v.startsWith("_")) v = v.substring(1);
        return v;
    }

    private static String norm(Register r) {
        return r.getName().toLowerCase(Locale.ROOT);
    }

    private static long signExtend16(long immU16) {
        long v = immU16 & 0xFFFFL;
        if ((v & 0x8000L) != 0) v |= ~0xFFFFL;
        return v;
    }

    private static int parseInt(String s, int fallback) {
        if (s == null) return fallback;
        String v = s.trim();
        if (v.isEmpty()) return fallback;
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return fallback;
        }
    }

    private static Long parseAddress(String s) {
        if (s == null) return null;
        String v = s.trim();
        if (v.isEmpty()) return null;
        try {
            if (v.startsWith("0x") || v.startsWith("0X")) {
                return Long.valueOf(Long.parseUnsignedLong(v.substring(2), 16) & U32_MASK);
            }
            return Long.valueOf(Long.parseUnsignedLong(v, 10) & U32_MASK);
        } catch (Exception e) {
            return null;
        }
    }

    private static long[] normalizeRange(long a, long b) {
        long s = a & U32_MASK;
        long e = b & U32_MASK;
        if (s <= e) return new long[] { s, e };
        return new long[] { e, s };
    }

    private static boolean isInRanges(long addr, List<long[]> ranges) {
        for (long[] r : ranges) {
            if (addr >= r[0] && addr <= r[1]) return true;
        }
        return false;
    }

    private static void coalesceRanges(List<long[]> ranges) {
        if (ranges.isEmpty()) return;
        Collections.sort(ranges, Comparator.comparingLong((long[] r) -> r[0]));
        List<long[]> out = new ArrayList<>();
        long[] cur = ranges.get(0).clone();

        for (int i = 1; i < ranges.size(); i++) {
            long[] r = ranges.get(i);
            if (r[0] <= cur[1] + 1) {
                if (r[1] > cur[1]) cur[1] = r[1];
            } else {
                out.add(cur);
                cur = r.clone();
            }
        }
        out.add(cur);

        ranges.clear();
        ranges.addAll(out);
    }

    private static String hex32(long v) {
        return String.format(Locale.ROOT, "0x%08X", v & U32_MASK);
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
