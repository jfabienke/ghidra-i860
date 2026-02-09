// Build an original-binary-only confidence map for i860 kernel recovery.
//
// This script scores fixed-size executable windows using byte heuristics and
// decoded control-flow quality, then emits:
//   1) per-window confidence JSON
//   2) generated allow/deny recovery map JSON for I860Analyze
//
// Run as postScript on an already-imported/analyzed program.
//
// Optional script args:
//   arg0: windows_json_path   (default: /tmp/i860_confidence_windows.json)
//   arg1: recovery_json_path  (default: /tmp/i860_recovery_generated.json)
//   arg2: window_size_bytes   (default: 256)
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class BuildConfidenceMap extends GhidraScript {

    private static final int DEFAULT_WINDOW_SIZE = 0x100;
    private static final String DEFAULT_WINDOWS_OUT = "/tmp/i860_confidence_windows.json";
    private static final String DEFAULT_RECOVERY_OUT = "/tmp/i860_recovery_generated.json";

    private Memory memory;
    private Listing listing;
    private AddressSpace space;
    private List<long[]> execRanges = new ArrayList<>();
    private List<long[]> embeddedObjects = new ArrayList<>();

    private static class WindowMetrics {
        long start;
        long end;
        int size;
        String blockName;

        int wordCount;
        int insnWords;
        int inRangeFlows;
        int outOfRangeFlows;
        int branchCount;
        int callCount;
        int returnCount;
        int delayCandidates;
        int delayComplete;
        int uniqueOpcodes;

        int asciiPct;
        int zeroPct;
        double entropy;
        int x86Score;
        int m68kScore;
        boolean hasMachOMagic;
        int machoCpuType;
        boolean overlapsEmbeddedObject;
        double maxWordRatio;
        double repeatAdjRatio;

        double score;
        String cls;
        boolean hardVeto;
        List<String> vetoReasons = new ArrayList<>();
    }

    private static class RangeLabel {
        long start;
        long end;
        String label;
        RangeLabel(long start, long end, String label) {
            this.start = start;
            this.end = end;
            this.label = label;
        }
    }

    @Override
    public void run() throws Exception {
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        String[] args = getScriptArgs();
        String windowsOut = args.length >= 1 && !args[0].trim().isEmpty()
            ? args[0].trim()
            : DEFAULT_WINDOWS_OUT;
        String recoveryOut = args.length >= 2 && !args[1].trim().isEmpty()
            ? args[1].trim()
            : DEFAULT_RECOVERY_OUT;

        int windowSize = DEFAULT_WINDOW_SIZE;
        if (args.length >= 3) {
            Integer parsed = parseIntArg(args[2]);
            if (parsed != null && parsed.intValue() >= 0x40 && parsed.intValue() <= 0x4000) {
                windowSize = parsed.intValue();
            }
        }

        buildExecRanges();
        embeddedObjects = detectEmbeddedObjects();

        List<WindowMetrics> windows = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;

            long bStart = block.getStart().getOffset();
            long bEnd = block.getEnd().getOffset();
            for (long wStart = bStart; wStart <= bEnd; wStart += windowSize) {
                if (monitor.isCancelled()) break;
                long wEnd = Math.min(wStart + windowSize - 1, bEnd);
                windows.add(analyzeWindow(block.getName(), wStart, wEnd));
            }
        }

        List<RangeLabel> allowRanges = buildAllowRanges(windows);
        List<RangeLabel> denyRanges = buildRanges(windows, "LOW", "confidence_low");

        writeWindowsJson(windowsOut, windows, allowRanges, denyRanges, windowSize);
        writeRecoveryJson(recoveryOut, allowRanges, denyRanges, windowSize);

        int high = 0, medium = 0, low = 0;
        for (WindowMetrics w : windows) {
            if ("HIGH".equals(w.cls)) high++;
            else if ("MEDIUM".equals(w.cls)) medium++;
            else low++;
        }

        printf("=== BuildConfidenceMap ===%n");
        printf("Program: %s%n", currentProgram.getName());
        printf("Window size: %d bytes%n", windowSize);
        printf("Windows: %d (HIGH=%d, MEDIUM=%d, LOW=%d)%n", windows.size(), high, medium, low);
        printf("Embedded objects: %d%n", embeddedObjects.size());
        printf("Allow ranges: %d%n", allowRanges.size());
        printf("Deny ranges:  %d%n", denyRanges.size());
        printf("Wrote: %s%n", windowsOut);
        printf("Wrote: %s%n", recoveryOut);
    }

    private void buildExecRanges() {
        execRanges.clear();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;
            execRanges.add(new long[]{block.getStart().getOffset(), block.getEnd().getOffset()});
        }
    }

    private WindowMetrics analyzeWindow(String blockName, long start, long end) throws Exception {
        WindowMetrics m = new WindowMetrics();
        m.start = start;
        m.end = end;
        m.blockName = blockName;
        m.size = (int)(end - start + 1);
        m.overlapsEmbeddedObject = overlapsEmbeddedObject(start, end);

        byte[] bytes = new byte[m.size];
        memory.getBytes(space.getAddress(start), bytes);

        analyzeByteFeatures(bytes, m);
        analyzeControlFlowFeatures(start, end, bytes, m);
        scoreWindow(m);
        return m;
    }

    private void analyzeByteFeatures(byte[] bytes, WindowMetrics m) {
        int[] freq = new int[256];
        int printable = 0;
        int zeros = 0;

        for (byte b : bytes) {
            int v = b & 0xFF;
            freq[v]++;
            if (v == 0) zeros++;
            if ((v >= 0x20 && v <= 0x7E) || v == 0x09 || v == 0x0A || v == 0x0D) {
                printable++;
            }
        }

        m.asciiPct = (printable * 100) / bytes.length;
        m.zeroPct = (zeros * 100) / bytes.length;

        double ent = 0.0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / (double) bytes.length;
            ent -= p * (Math.log(p) / Math.log(2.0));
        }
        m.entropy = ent;

        int x86 = 0;
        for (int i = 0; i + 1 < bytes.length; i++) {
            int b0 = bytes[i] & 0xFF;
            int b1 = bytes[i + 1] & 0xFF;
            if (b0 == 0x55 && b1 == 0x89) x86 += 3;
            else if (b0 == 0x55 && b1 == 0x8B) x86 += 3;
            else if (b0 == 0x5D && b1 == 0xC3) x86 += 3;
            else if (b0 == 0xC3) x86 += 2;
            else if (b0 == 0xC2) x86 += 1;
            else if (b0 == 0xE8) x86 += 2;
            else if (b0 == 0xE9) x86 += 1;
            else if (b0 == 0x83 && b1 == 0xEC) x86 += 2;
            else if (b0 == 0x83 && b1 == 0xC4) x86 += 2;
            else if (b0 == 0xFF && (b1 & 0x38) == 0x10) x86 += 1;
        }
        m.x86Score = x86;

        int m68k = 0;
        for (int i = 0; i + 1 < bytes.length; i += 2) {
            int w = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
            if (w == 0x4E75 || w == 0x4E56 || w == 0x4E5E) m68k += 3;
            else if (w == 0x4E71) m68k += 2;
            else if ((w & 0xFFF0) == 0x4EA0) m68k += 2;
            else if (w == 0x4EB9) m68k += 2;
            else if ((w & 0xFF00) == 0x4800) m68k += 1;
            else if ((w & 0xFF00) == 0x4C00) m68k += 1;
            else if ((w & 0xFF00) == 0x2F00) m68k += 1;
        }
        m.m68kScore = m68k;

        boolean macho = false;
        int machoCpu = 0;
        for (int i = 0; i + 7 < bytes.length; i += 4) {
            int w32 = ((bytes[i] & 0xFF) << 24)
                    | ((bytes[i + 1] & 0xFF) << 16)
                    | ((bytes[i + 2] & 0xFF) << 8)
                    | (bytes[i + 3] & 0xFF);
            if (w32 == 0xFEEDFACE || w32 == 0xCEFAEDFE) {
                macho = true;
                boolean be = (w32 == 0xFEEDFACE);
                if (be) {
                    machoCpu = ((bytes[i + 4] & 0xFF) << 24)
                            | ((bytes[i + 5] & 0xFF) << 16)
                            | ((bytes[i + 6] & 0xFF) << 8)
                            | (bytes[i + 7] & 0xFF);
                } else {
                    machoCpu = (bytes[i + 4] & 0xFF)
                            | ((bytes[i + 5] & 0xFF) << 8)
                            | ((bytes[i + 6] & 0xFF) << 16)
                            | ((bytes[i + 7] & 0xFF) << 24);
                }
                break;
            }
        }
        m.hasMachOMagic = macho;
        m.machoCpuType = machoCpu;

        Map<Integer, Integer> wordFreq = new HashMap<>();
        int words = 0;
        int adjRepeat = 0;
        Integer prev = null;
        int maxCount = 0;
        for (int i = 0; i + 3 < bytes.length; i += 4) {
            int w = readWordLE(bytes, i);
            words++;
            int c = wordFreq.getOrDefault(Integer.valueOf(w), Integer.valueOf(0)).intValue() + 1;
            wordFreq.put(Integer.valueOf(w), Integer.valueOf(c));
            if (c > maxCount) maxCount = c;
            if (prev != null && prev.intValue() == w) adjRepeat++;
            prev = Integer.valueOf(w);
        }

        if (words > 0) {
            m.maxWordRatio = (double) maxCount / (double) words;
            if (words > 1) {
                m.repeatAdjRatio = (double) adjRepeat / (double) (words - 1);
            } else {
                m.repeatAdjRatio = 0.0;
            }
        } else {
            m.maxWordRatio = 0.0;
            m.repeatAdjRatio = 0.0;
        }
    }

    private void analyzeControlFlowFeatures(long start, long end, byte[] bytes, WindowMetrics m) {
        int words = 0;
        int insn = 0;
        int inFlow = 0;
        int outFlow = 0;
        int calls = 0;
        int branches = 0;
        int returns = 0;
        int delayCandidates = 0;
        int delayComplete = 0;

        Set<Integer> opcodes = new HashSet<>();

        for (long off = start; off <= end - 3; off += 4) {
            if (monitor.isCancelled()) break;
            words++;

            int byteOff = (int)(off - start);
            int rawWord = readWordLE(bytes, byteOff);

            Address addr = space.getAddress(off);
            Instruction ins = listing.getInstructionAt(addr);
            if (ins == null) continue;
            if (ins.getAddress().getOffset() != off) continue;

            insn++;
            int op6 = (rawWord >>> 26) & 0x3F;
            opcodes.add(Integer.valueOf(op6));

            FlowType ft = ins.getFlowType();
            if (ft != null) {
                if (ft.isCall()) calls++;
                if (ft.isJump() || ft.isConditional() || ft.isTerminal()) branches++;
            }

            for (Address target : ins.getFlows()) {
                if (target == null) continue;
                if (isInExecRange(target.getOffset())) inFlow++;
                else outFlow++;
            }

            if (isReturnInstruction(ins, rawWord)) returns++;

            if (hasDelaySlot(rawWord)) {
                delayCandidates++;
                long next = off + 4;
                if (next <= end && isInExecRange(next)) {
                    Instruction ds = listing.getInstructionAt(space.getAddress(next));
                    if (ds != null && ds.getAddress().getOffset() == next) {
                        delayComplete++;
                    }
                }
            }
        }

        m.wordCount = words;
        m.insnWords = insn;
        m.inRangeFlows = inFlow;
        m.outOfRangeFlows = outFlow;
        m.callCount = calls;
        m.branchCount = branches;
        m.returnCount = returns;
        m.delayCandidates = delayCandidates;
        m.delayComplete = delayComplete;
        m.uniqueOpcodes = opcodes.size();
    }

    private void scoreWindow(WindowMetrics m) {
        double score = 50.0;

        double insnDensity = m.wordCount > 0 ? ((double)m.insnWords / (double)m.wordCount) : 0.0;
        double flowTotal = (double)(m.inRangeFlows + m.outOfRangeFlows);
        double inFlowRatio = flowTotal > 0.0 ? ((double)m.inRangeFlows / flowTotal) : 0.5;
        double delayRatio = m.delayCandidates > 0
            ? ((double)m.delayComplete / (double)m.delayCandidates)
            : 0.5;

        score += insnDensity * 30.0;
        score += (inFlowRatio - 0.5) * 30.0;
        score += (delayRatio - 0.5) * 10.0;
        score += Math.min(8.0, (double)m.uniqueOpcodes);

        if (m.returnCount > 0) score += 8.0;
        if (m.callCount > 0) score += 4.0;
        if (m.branchCount > 0) score += 2.0;

        score -= ((double)m.zeroPct) * 0.20;
        if (m.asciiPct > 30) score -= ((double)(m.asciiPct - 30)) * 0.20;
        if (m.outOfRangeFlows > 0) score -= Math.min(20.0, (double)m.outOfRangeFlows * 3.0);
        score -= Math.min(25.0, (double)m.x86Score * 0.6);
        score -= Math.min(25.0, (double)m.m68kScore * 0.6);

        if (m.maxWordRatio > 0.25) score -= (m.maxWordRatio - 0.25) * 40.0;
        if (m.repeatAdjRatio > 0.30) score -= (m.repeatAdjRatio - 0.30) * 25.0;

        if (m.entropy >= 4.0 && m.entropy <= 7.2) score += 3.0;
        else score -= 3.0;

        boolean veto = false;
        List<String> reasons = new ArrayList<>();
        if (m.hasMachOMagic) {
            veto = true;
            reasons.add("macho_magic");
        }
        if (m.overlapsEmbeddedObject) {
            veto = true;
            reasons.add("embedded_object");
        }
        if (m.zeroPct > 85) {
            veto = true;
            reasons.add("zero_pct>85");
        }
        if (m.asciiPct > 80) {
            veto = true;
            reasons.add("ascii_pct>80");
        }
        if (m.x86Score >= 40) {
            veto = true;
            reasons.add("x86_score>=40");
        }
        if (m.m68kScore >= 40) {
            veto = true;
            reasons.add("m68k_score>=40");
        }

        if (veto) score = Math.min(score, 20.0);

        if (score < 0.0) score = 0.0;
        if (score > 100.0) score = 100.0;

        m.score = score;
        m.hardVeto = veto;
        m.vetoReasons = reasons;

        if (m.score >= 65.0 && !m.hardVeto) m.cls = "HIGH";
        else if (m.score >= 45.0 && !m.hardVeto) m.cls = "MEDIUM";
        else m.cls = "LOW";
    }

    private List<RangeLabel> buildRanges(List<WindowMetrics> windows, String targetClass, String label) {
        List<RangeLabel> out = new ArrayList<>();
        RangeLabel cur = null;
        for (WindowMetrics w : windows) {
            if (!targetClass.equals(w.cls)) continue;
            if (cur == null) {
                cur = new RangeLabel(w.start, w.end, label);
            } else if (w.start == cur.end + 1) {
                cur.end = w.end;
            } else {
                out.add(cur);
                cur = new RangeLabel(w.start, w.end, label);
            }
        }
        if (cur != null) out.add(cur);
        return out;
    }

    // Allow ranges should include both HIGH and MEDIUM confidence so that
    // low-confidence zones are excluded without starving seed discovery.
    private List<RangeLabel> buildAllowRanges(List<WindowMetrics> windows) {
        List<RangeLabel> out = new ArrayList<>();
        RangeLabel cur = null;
        for (WindowMetrics w : windows) {
            if ("LOW".equals(w.cls)) continue;
            if (cur == null) {
                cur = new RangeLabel(w.start, w.end, "confidence_candidate");
            } else if (w.start == cur.end + 1) {
                cur.end = w.end;
            } else {
                out.add(cur);
                cur = new RangeLabel(w.start, w.end, "confidence_candidate");
            }
        }
        if (cur != null) out.add(cur);
        return out;
    }

    private void writeWindowsJson(
        String path,
        List<WindowMetrics> windows,
        List<RangeLabel> allowRanges,
        List<RangeLabel> denyRanges,
        int windowSize
    ) throws Exception {
        int high = 0, medium = 0, low = 0;
        for (WindowMetrics w : windows) {
            if ("HIGH".equals(w.cls)) high++;
            else if ("MEDIUM".equals(w.cls)) medium++;
            else low++;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"meta\": {\n");
        sb.append("    \"name\": \"i860-confidence-windows\",\n");
        sb.append("    \"version\": \"1\",\n");
        sb.append("    \"generated_at\": \"").append(jsonEscape(Instant.now().toString())).append("\",\n");
        sb.append("    \"program\": \"").append(jsonEscape(currentProgram.getName())).append("\",\n");
        sb.append("    \"language\": \"").append(jsonEscape(currentProgram.getLanguageID().toString())).append("\",\n");
        sb.append("    \"compiler\": \"").append(jsonEscape(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append("\",\n");
        sb.append("    \"window_size\": ").append(windowSize).append("\n");
        sb.append("  },\n");
        sb.append("  \"summary\": {\n");
        sb.append("    \"windows\": ").append(windows.size()).append(",\n");
        sb.append("    \"high\": ").append(high).append(",\n");
        sb.append("    \"medium\": ").append(medium).append(",\n");
        sb.append("    \"low\": ").append(low).append(",\n");
        sb.append("    \"allow_ranges\": ").append(allowRanges.size()).append(",\n");
        sb.append("    \"deny_ranges\": ").append(denyRanges.size()).append("\n");
        sb.append("  },\n");

        sb.append("  \"allow_ranges\": [\n");
        for (int i = 0; i < allowRanges.size(); i++) {
            RangeLabel r = allowRanges.get(i);
            sb.append("    {\"start\":\"").append(hex(r.start)).append("\",\"end\":\"")
                .append(hex(r.end)).append("\",\"name\":\"").append(r.label).append("\"}");
            if (i + 1 < allowRanges.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"deny_ranges\": [\n");
        for (int i = 0; i < denyRanges.size(); i++) {
            RangeLabel r = denyRanges.get(i);
            sb.append("    {\"start\":\"").append(hex(r.start)).append("\",\"end\":\"")
                .append(hex(r.end)).append("\",\"name\":\"").append(r.label).append("\"}");
            if (i + 1 < denyRanges.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"windows\": [\n");
        for (int i = 0; i < windows.size(); i++) {
            WindowMetrics w = windows.get(i);
            sb.append("    {\n");
            sb.append("      \"start\": \"").append(hex(w.start)).append("\",\n");
            sb.append("      \"end\": \"").append(hex(w.end)).append("\",\n");
            sb.append("      \"size\": ").append(w.size).append(",\n");
            sb.append("      \"block\": \"").append(jsonEscape(w.blockName)).append("\",\n");
            sb.append("      \"class\": \"").append(w.cls).append("\",\n");
            sb.append("      \"score\": ").append(String.format(Locale.ROOT, "%.2f", w.score)).append(",\n");
            sb.append("      \"hard_veto\": ").append(w.hardVeto ? "true" : "false").append(",\n");
            sb.append("      \"veto_reasons\": [");
            for (int j = 0; j < w.vetoReasons.size(); j++) {
                sb.append("\"").append(jsonEscape(w.vetoReasons.get(j))).append("\"");
                if (j + 1 < w.vetoReasons.size()) sb.append(",");
            }
            sb.append("],\n");
            sb.append("      \"features\": {\n");
            sb.append("        \"word_count\": ").append(w.wordCount).append(",\n");
            sb.append("        \"insn_words\": ").append(w.insnWords).append(",\n");
            sb.append("        \"in_range_flows\": ").append(w.inRangeFlows).append(",\n");
            sb.append("        \"out_of_range_flows\": ").append(w.outOfRangeFlows).append(",\n");
            sb.append("        \"branch_count\": ").append(w.branchCount).append(",\n");
            sb.append("        \"call_count\": ").append(w.callCount).append(",\n");
            sb.append("        \"return_count\": ").append(w.returnCount).append(",\n");
            sb.append("        \"delay_candidates\": ").append(w.delayCandidates).append(",\n");
            sb.append("        \"delay_complete\": ").append(w.delayComplete).append(",\n");
            sb.append("        \"unique_opcodes\": ").append(w.uniqueOpcodes).append(",\n");
            sb.append("        \"ascii_pct\": ").append(w.asciiPct).append(",\n");
            sb.append("        \"zero_pct\": ").append(w.zeroPct).append(",\n");
            sb.append("        \"entropy\": ").append(String.format(Locale.ROOT, "%.3f", w.entropy)).append(",\n");
            sb.append("        \"x86_score\": ").append(w.x86Score).append(",\n");
            sb.append("        \"m68k_score\": ").append(w.m68kScore).append(",\n");
            sb.append("        \"has_macho_magic\": ").append(w.hasMachOMagic ? "true" : "false").append(",\n");
            sb.append("        \"macho_cpu_type\": ").append(w.machoCpuType).append(",\n");
            sb.append("        \"overlaps_embedded_object\": ").append(w.overlapsEmbeddedObject ? "true" : "false").append(",\n");
            sb.append("        \"max_word_ratio\": ").append(String.format(Locale.ROOT, "%.4f", w.maxWordRatio)).append(",\n");
            sb.append("        \"repeat_adj_ratio\": ").append(String.format(Locale.ROOT, "%.4f", w.repeatAdjRatio)).append("\n");
            sb.append("      }\n");
            sb.append("    }");
            if (i + 1 < windows.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");

        PrintWriter pw = new PrintWriter(new FileWriter(path));
        pw.print(sb.toString());
        pw.close();
    }

    private void writeRecoveryJson(
        String path,
        List<RangeLabel> allowRanges,
        List<RangeLabel> denyRanges,
        int windowSize
    ) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"meta\": {\n");
        sb.append("    \"name\": \"i860-generated-recovery-map\",\n");
        sb.append("    \"version\": \"1\",\n");
        sb.append("    \"generated_at\": \"").append(jsonEscape(Instant.now().toString())).append("\",\n");
        sb.append("    \"source_program\": \"").append(jsonEscape(currentProgram.getName())).append("\",\n");
        sb.append("    \"window_size\": ").append(windowSize).append(",\n");
        sb.append("    \"notes\": \"Generated from original binary window confidence scoring\"\n");
        sb.append("  },\n");

        sb.append("  \"allow_ranges\": [\n");
        for (int i = 0; i < allowRanges.size(); i++) {
            RangeLabel r = allowRanges.get(i);
            sb.append("    {\"start\":\"").append(hex(r.start)).append("\",\"end\":\"")
                .append(hex(r.end)).append("\",\"name\":\"").append(r.label).append("\"}");
            if (i + 1 < allowRanges.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"deny_ranges\": [\n");
        for (int i = 0; i < denyRanges.size(); i++) {
            RangeLabel r = denyRanges.get(i);
            sb.append("    {\"start\":\"").append(hex(r.start)).append("\",\"end\":\"")
                .append(hex(r.end)).append("\",\"name\":\"").append(r.label).append("\"}");
            if (i + 1 < denyRanges.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"seeds\": []\n");
        sb.append("}\n");

        PrintWriter pw = new PrintWriter(new FileWriter(path));
        pw.print(sb.toString());
        pw.close();
    }

    private boolean isInExecRange(long addr) {
        for (long[] r : execRanges) {
            if (addr >= r[0] && addr <= r[1]) return true;
        }
        return false;
    }

    private boolean overlapsEmbeddedObject(long start, long end) {
        for (long[] obj : embeddedObjects) {
            if (start <= obj[1] && end >= obj[0]) return true;
        }
        return false;
    }

    private boolean hasDelaySlot(int word) {
        int op6 = (word >>> 26) & 0x3F;
        if (op6 == 0x1A || op6 == 0x1B || op6 == 0x1D || op6 == 0x1F
            || op6 == 0x2D || op6 == 0x10) {
            return true;
        }
        if (op6 == 0x13) {
            int escop = word & 0x7;
            return escop == 0x2; // calli
        }
        return false;
    }

    private boolean isReturnInstruction(Instruction insn, int rawWord) {
        String mnemonic = insn.getMnemonicString();
        if ("ret".equals(mnemonic) || "_ret".equals(mnemonic)) return true;
        if (!"bri".equals(mnemonic) && !"_bri".equals(mnemonic)) return false;
        int op6 = (rawWord >>> 26) & 0x3F;
        int src1 = (rawWord >>> 11) & 0x1F;
        return op6 == 0x10 && src1 == 1;
    }

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
                int wordBE = ((bytes[i] & 0xFF) << 24)
                        | ((bytes[i + 1] & 0xFF) << 16)
                        | ((bytes[i + 2] & 0xFF) << 8)
                        | (bytes[i + 3] & 0xFF);

                boolean isBE = (wordBE == 0xFEEDFACE);
                boolean isLE = (wordBE == 0xCEFAEDFE);
                if (!isBE && !isLE) continue;

                long addr = startOff + i;
                int cpuType;
                if (isBE) {
                    cpuType = ((bytes[i + 4] & 0xFF) << 24)
                            | ((bytes[i + 5] & 0xFF) << 16)
                            | ((bytes[i + 6] & 0xFF) << 8)
                            | (bytes[i + 7] & 0xFF);
                } else {
                    cpuType = (bytes[i + 4] & 0xFF)
                            | ((bytes[i + 5] & 0xFF) << 8)
                            | ((bytes[i + 6] & 0xFF) << 16)
                            | ((bytes[i + 7] & 0xFF) << 24);
                }
                magics.add(new long[]{addr, cpuType});
            }

            for (int m = 0; m < magics.size(); m++) {
                long addr = magics.get(m)[0];
                int cpuType = (int)magics.get(m)[1];

                if (addr == startOff) continue;
                if (cpuType == 15) continue;

                int base = (int)(addr - startOff);
                boolean objBE;
                {
                    int w = ((bytes[base] & 0xFF) << 24)
                          | ((bytes[base + 1] & 0xFF) << 16)
                          | ((bytes[base + 2] & 0xFF) << 8)
                          | (bytes[base + 3] & 0xFF);
                    objBE = (w == 0xFEEDFACE);
                }

                int ncmds = readMachInt(bytes, base + 16, objBE);
                int sizeOfCmds = readMachInt(bytes, base + 20, objBE);

                long maxFileEnd = 28L + (long)sizeOfCmds;
                int cmdOff = base + 28;
                for (int c = 0; c < ncmds && cmdOff + 8 <= bytes.length; c++) {
                    int cmd = readMachInt(bytes, cmdOff, objBE);
                    int cmdSize = readMachInt(bytes, cmdOff + 4, objBE);
                    if (cmdSize < 8) break;
                    if (cmd == 1 && cmdOff + 40 <= bytes.length) {
                        int fileOff = readMachInt(bytes, cmdOff + 32, objBE);
                        int fileSize = readMachInt(bytes, cmdOff + 36, objBE);
                        long segEnd = (long)fileOff + (long)fileSize;
                        if (segEnd > maxFileEnd) maxFileEnd = segEnd;
                    }
                    cmdOff += cmdSize;
                }

                long objEnd = Math.min(addr + maxFileEnd - 1, endOff);
                objects.add(new long[]{addr, objEnd});
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
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        return merged;
    }

    private static int readMachInt(byte[] data, int offset, boolean bigEndian) {
        if (bigEndian) {
            return ((data[offset] & 0xFF) << 24)
                 | ((data[offset + 1] & 0xFF) << 16)
                 | ((data[offset + 2] & 0xFF) << 8)
                 | (data[offset + 3] & 0xFF);
        }
        return (data[offset] & 0xFF)
             | ((data[offset + 1] & 0xFF) << 8)
             | ((data[offset + 2] & 0xFF) << 16)
             | ((data[offset + 3] & 0xFF) << 24);
    }

    private static int readWordLE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
             | ((data[offset + 1] & 0xFF) << 8)
             | ((data[offset + 2] & 0xFF) << 16)
             | ((data[offset + 3] & 0xFF) << 24);
    }

    private static String hex(long v) {
        return String.format("0x%08X", v);
    }

    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int)c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private static Integer parseIntArg(String s) {
        try {
            return Integer.valueOf(Integer.parseInt(s.trim()));
        } catch (Exception e) {
            return null;
        }
    }
}
