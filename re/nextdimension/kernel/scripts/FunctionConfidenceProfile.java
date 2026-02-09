// Function confidence profiler for i860 reverse engineering.
//
// Produces:
//   - function_confidence.csv
//   - high_conf_functions.txt
//   - suspect_functions.txt
//
// Scoring heuristics emphasize:
//   - CFG sanity (out-of-range flows, delay-slot closure, return-like exits)
//   - Opcode/mnemonic diversity and repetition checks
//   - bri register patterns (dispatch-like vs suspicious r0)
//   - Cross-evidence tags (MMIO 0x401C, FP-heavy, likely PostScript refs)
//
// Script args (optional):
//   arg0: output directory (default: /tmp)
//   arg1: minimum function size in bytes (default: 24)
//   arg2: high-confidence threshold (default: 70)
//   arg3: suspect threshold (default: 45)
//   arg4: recovery-map output JSON path (optional; default disabled)
//   arg5: include MEDIUM functions as seeds (default: true)
//   arg6: minimum score for MEDIUM seed inclusion (default: 55)
//   arg7: minimum deny-range size in bytes (default: 64)
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class FunctionConfidenceProfile extends GhidraScript {

    private static final int DEFAULT_MIN_BYTES = 24;
    private static final int DEFAULT_HIGH_THRESHOLD = 70;
    private static final int DEFAULT_SUSPECT_THRESHOLD = 45;
    private static final int DEFAULT_SEED_MIN_SCORE = 55;
    private static final int DEFAULT_MIN_DENY_RANGE_BYTES = 64;
    private static final long MMIO_OFFSET_401C = 0x401CL;

    private static class FunctionProfile {
        Address entry;
        String name;
        long sizeBytes;
        int insnCount;
        List<long[]> bodyRanges = new ArrayList<>();

        int callCount;
        int branchCount;
        int returnCount;
        int inRangeFlows;
        int outOfRangeFlows;

        int delayCandidates;
        int delayMissing;

        int loadCount;
        int storeCount;
        int fpCount;

        int briCount;
        int briR0;
        int briR1;
        int briOther;

        int mmio401cHits;
        int psRefHits;

        int nullWordCount;
        double nullRatio;

        int uniqueMnemonics;
        String dominantMnemonic = "";
        double dominantMnemonicRatio;

        double maxWordRatio;
        double adjacentRepeatRatio;
        double outFlowRatio;
        double fpRatio;
        double loadRatio;
        double storeRatio;

        double score;
        String cls;
        List<String> reasons = new ArrayList<>();
        Set<String> tags = new HashSet<>();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = (args.length >= 1 && !args[0].trim().isEmpty()) ? args[0].trim() : "/tmp";
        int minBytes = parseIntArg(args, 1, DEFAULT_MIN_BYTES);
        int highThreshold = parseIntArg(args, 2, DEFAULT_HIGH_THRESHOLD);
        int suspectThreshold = parseIntArg(args, 3, DEFAULT_SUSPECT_THRESHOLD);
        String recoveryMapPath = parseStringArg(args, 4, "");
        boolean includeMediumSeeds = parseBooleanArg(args, 5, true);
        int mediumSeedMinScore = parseIntArg(args, 6, DEFAULT_SEED_MIN_SCORE);
        int minDenyRangeBytes = parseIntArg(args, 7, DEFAULT_MIN_DENY_RANGE_BYTES);

        File dir = new File(outDir);
        if (!dir.exists()) dir.mkdirs();

        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();

        List<FunctionProfile> profiles = new ArrayList<>();
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = fi.next();
            if (f == null) continue;
            if (f.getBody().getNumAddresses() < minBytes) continue;
            FunctionProfile p = analyzeFunction(listing, memory, f, highThreshold, suspectThreshold);
            profiles.add(p);
        }

        Collections.sort(profiles, Comparator.comparingDouble((FunctionProfile p) -> p.score).reversed());

        File csv = new File(dir, "function_confidence.csv");
        File highTxt = new File(dir, "high_conf_functions.txt");
        File suspectTxt = new File(dir, "suspect_functions.txt");

        writeCsv(csv, profiles);
        writeHigh(highTxt, profiles, highThreshold);
        writeSuspect(suspectTxt, profiles, suspectThreshold);
        File recoveryMap = null;
        if (!recoveryMapPath.isEmpty()) {
            recoveryMap = new File(recoveryMapPath);
            writeRecoveryMap(recoveryMap, profiles, includeMediumSeeds, mediumSeedMinScore, minDenyRangeBytes);
        }

        int high = 0, medium = 0, suspect = 0;
        for (FunctionProfile p : profiles) {
            if ("HIGH".equals(p.cls)) high++;
            else if ("SUSPECT".equals(p.cls)) suspect++;
            else medium++;
        }

        printf("=== FunctionConfidenceProfile ===%n");
        printf("Program:  %s%n", currentProgram.getName());
        printf("Profiles: %d (HIGH=%d MEDIUM=%d SUSPECT=%d)%n", profiles.size(), high, medium, suspect);
        printf("Output:   %s%n", csv.getAbsolutePath());
        printf("Output:   %s%n", highTxt.getAbsolutePath());
        printf("Output:   %s%n", suspectTxt.getAbsolutePath());
        if (recoveryMap != null) {
            printf("Output:   %s%n", recoveryMap.getAbsolutePath());
        }
    }

    private FunctionProfile analyzeFunction(
        Listing listing,
        Memory memory,
        Function f,
        int highThreshold,
        int suspectThreshold
    ) {
        FunctionProfile p = new FunctionProfile();
        p.entry = f.getEntryPoint();
        p.name = f.getName();
        p.sizeBytes = f.getBody().getNumAddresses();
        AddressRangeIterator ri = f.getBody().getAddressRanges();
        while (ri.hasNext()) {
            AddressRange r = ri.next();
            p.bodyRanges.add(new long[] { r.getMinAddress().getOffset(), r.getMaxAddress().getOffset() });
        }

        Map<String, Integer> mnemonicCounts = new HashMap<>();
        Map<Integer, Integer> wordCounts = new HashMap<>();

        Integer prevWord = null;
        int adjRepeat = 0;
        int maxWordCount = 0;

        InstructionIterator ii = listing.getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction ins = ii.next();
            p.insnCount++;

            FlowType ft = ins.getFlowType();
            if (ft != null) {
                if (ft.isCall()) p.callCount++;
                if (ft.isConditional() || ft.isJump() || ft.isTerminal()) p.branchCount++;
            }

            for (Address target : ins.getFlows()) {
                if (target == null) continue;
                if (memory.contains(target)) p.inRangeFlows++;
                else p.outOfRangeFlows++;
            }

            String mn = ins.getMnemonicString().toLowerCase(Locale.ROOT);
            mnemonicCounts.put(mn, Integer.valueOf(mnemonicCounts.getOrDefault(mn, Integer.valueOf(0)).intValue() + 1));

            if (isLoadMnemonic(mn)) p.loadCount++;
            if (isStoreMnemonic(mn)) p.storeCount++;
            if (isFpMnemonic(mn)) p.fpCount++;

            if (ins.toString().toLowerCase(Locale.ROOT).contains("0x401c(")) {
                p.mmio401cHits++;
            }

            int nops = ins.getNumOperands();
            for (int opIndex = 0; opIndex < nops; opIndex++) {
                Scalar s = ins.getScalar(opIndex);
                if (s == null) continue;
                long u = s.getUnsignedValue();
                long u32 = u & 0xFFFFFFFFL;
                if (u32 == MMIO_OFFSET_401C) {
                    p.mmio401cHits++;
                }
                if (isLikelyPostScriptRef(u32)) {
                    p.psRefHits++;
                }
            }

            Integer word = readWord(memory, ins.getAddress());
            if (word != null) {
                int w = word.intValue();
                if (w == 0) p.nullWordCount++;

                int c = wordCounts.getOrDefault(Integer.valueOf(w), Integer.valueOf(0)).intValue() + 1;
                wordCounts.put(Integer.valueOf(w), Integer.valueOf(c));
                if (c > maxWordCount) maxWordCount = c;

                if (prevWord != null && prevWord.intValue() == w) adjRepeat++;
                prevWord = Integer.valueOf(w);

                int op6 = (w >>> 26) & 0x3F;
                if (op6 == 0x10) { // bri
                    p.briCount++;
                    int src1 = (w >>> 11) & 0x1F;
                    if (src1 == 0) p.briR0++;
                    else if (src1 == 1) p.briR1++;
                    else p.briOther++;
                }

                if (hasDelaySlot(w)) {
                    p.delayCandidates++;
                    try {
                        Address next = ins.getAddress().add(4);
                        Instruction ds = listing.getInstructionAt(next);
                        if (ds == null || !f.getBody().contains(next)) {
                            p.delayMissing++;
                        }
                    } catch (Exception e) {
                        p.delayMissing++;
                    }
                }

                if (isReturnInstruction(ins, w)) {
                    p.returnCount++;
                }
            }
        }

        p.uniqueMnemonics = mnemonicCounts.size();
        int domCount = 0;
        String dom = "";
        for (Map.Entry<String, Integer> e : mnemonicCounts.entrySet()) {
            if (e.getValue().intValue() > domCount) {
                domCount = e.getValue().intValue();
                dom = e.getKey();
            }
        }
        p.dominantMnemonic = dom;
        if (p.insnCount > 0) {
            p.dominantMnemonicRatio = (double) domCount / (double) p.insnCount;
            p.maxWordRatio = (double) maxWordCount / (double) p.insnCount;
            p.nullRatio = (double) p.nullWordCount / (double) p.insnCount;
            p.fpRatio = (double) p.fpCount / (double) p.insnCount;
            p.loadRatio = (double) p.loadCount / (double) p.insnCount;
            p.storeRatio = (double) p.storeCount / (double) p.insnCount;
            if (p.insnCount > 1) {
                p.adjacentRepeatRatio = (double) adjRepeat / (double) (p.insnCount - 1);
            } else {
                p.adjacentRepeatRatio = 0.0;
            }
        }

        int totalFlows = p.inRangeFlows + p.outOfRangeFlows;
        p.outFlowRatio = totalFlows > 0 ? (double) p.outOfRangeFlows / (double) totalFlows : 0.0;

        scoreFunction(p, highThreshold, suspectThreshold);
        return p;
    }

    private void scoreFunction(FunctionProfile p, int highThreshold, int suspectThreshold) {
        double score = 50.0;
        List<String> reasons = p.reasons;

        if (p.returnCount > 0) {
            score += 18.0;
            p.tags.add("RETURN_LIKE");
        } else {
            score -= 10.0;
            reasons.add("no_return_like_terminator");
        }

        if (p.outOfRangeFlows == 0) {
            score += 8.0;
        } else {
            score -= Math.min(30.0, (double) p.outOfRangeFlows * 4.0);
            reasons.add("out_of_range_flows=" + p.outOfRangeFlows);
        }

        if (p.delayCandidates > 0) {
            if (p.delayMissing == 0) {
                score += 8.0;
            } else {
                score -= Math.min(20.0, (double) p.delayMissing * 5.0);
                reasons.add("missing_delay_slots=" + p.delayMissing);
            }
        }

        score += Math.min(12.0, (double) p.uniqueMnemonics);

        if (p.dominantMnemonicRatio > 0.60) {
            score -= Math.min(18.0, (p.dominantMnemonicRatio - 0.60) * 50.0);
            reasons.add("dominant_mnemonic=" + p.dominantMnemonic);
        }
        if (p.maxWordRatio > 0.25) {
            score -= Math.min(25.0, (p.maxWordRatio - 0.25) * 80.0);
            reasons.add("repeated_words");
        }
        if (p.adjacentRepeatRatio > 0.30) {
            score -= Math.min(20.0, (p.adjacentRepeatRatio - 0.30) * 60.0);
            reasons.add("adjacent_word_repetition");
        }
        if (p.nullRatio > 0.50) {
            score -= 30.0;
            reasons.add("null_ratio>50%");
        }

        if (p.briR0 > 0) {
            score -= Math.min(16.0, (double) p.briR0 * 4.0);
            reasons.add("bri_r0=" + p.briR0);
        }
        if (p.briOther > 0) {
            score += 4.0;
            p.tags.add("INDIRECT_DISPATCH");
        }

        if (p.mmio401cHits > 0) {
            score += 8.0;
            p.tags.add("MMIO_401C");
        }
        if (p.fpRatio >= 0.25) {
            score += 6.0;
            p.tags.add("FP_HEAVY");
        } else if (p.fpRatio >= 0.12) {
            score += 3.0;
            p.tags.add("FP_MIXED");
        }
        if (p.psRefHits > 0) {
            score += 5.0;
            p.tags.add("PS_REF");
        }

        if (p.loadRatio > 0.80 && p.storeRatio < 0.05 && p.branchCount == 0) {
            score -= 10.0;
            reasons.add("load_dominant_no_control");
        }

        if (score < 0.0) score = 0.0;
        if (score > 100.0) score = 100.0;
        p.score = score;

        boolean hardSuspect =
            p.nullRatio > 0.50 ||
            (p.outOfRangeFlows >= 3 && p.outFlowRatio > 0.20) ||
            (p.insnCount >= 8 && p.delayCandidates > 0 && p.delayMissing > 0) ||
            (p.dominantMnemonicRatio > 0.85 && p.insnCount >= 12);

        if (hardSuspect || p.score <= suspectThreshold) {
            p.cls = "SUSPECT";
        } else if (p.score >= highThreshold) {
            p.cls = "HIGH";
        } else {
            p.cls = "MEDIUM";
        }
    }

    private void writeCsv(File out, List<FunctionProfile> profiles) throws Exception {
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        pw.println(
            "address,name,size_bytes,insns,score,class,reasons,tags," +
            "null_ratio,out_flow_ratio,delay_missing,returns,bri_r0,bri_r1,bri_other," +
            "mmio_401c_hits,fp_ratio,load_ratio,store_ratio,dominant_mnemonic,dominant_ratio," +
            "max_word_ratio,adjacent_repeat_ratio"
        );

        for (FunctionProfile p : profiles) {
            pw.printf(
                Locale.ROOT,
                "%s,%s,%d,%d,%.2f,%s,%s,%s,%.4f,%.4f,%d,%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%s,%.4f,%.4f,%.4f%n",
                p.entry,
                csvEscape(p.name),
                p.sizeBytes,
                p.insnCount,
                p.score,
                p.cls,
                csvEscape(String.join("|", p.reasons)),
                csvEscape(String.join("|", sortStrings(p.tags))),
                p.nullRatio,
                p.outFlowRatio,
                p.delayMissing,
                p.returnCount,
                p.briR0,
                p.briR1,
                p.briOther,
                p.mmio401cHits,
                p.fpRatio,
                p.loadRatio,
                p.storeRatio,
                csvEscape(p.dominantMnemonic),
                p.dominantMnemonicRatio,
                p.maxWordRatio,
                p.adjacentRepeatRatio
            );
        }
        pw.close();
    }

    private void writeHigh(File out, List<FunctionProfile> profiles, int highThreshold) throws Exception {
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        int count = 0;
        for (FunctionProfile p : profiles) {
            if ("HIGH".equals(p.cls)) count++;
        }

        pw.printf("High-Confidence Functions (threshold >= %d)%n", highThreshold);
        pw.printf("Program: %s%n", currentProgram.getName());
        pw.printf("Count: %d%n%n", count);
        pw.println("Address       Score  Insns  Size  Tags                      Name");
        pw.println("------------  -----  -----  ----  ------------------------  -----------------------------");
        for (FunctionProfile p : profiles) {
            if (!"HIGH".equals(p.cls)) continue;
            pw.printf(
                Locale.ROOT,
                "%-12s  %5.1f  %5d  %4d  %-24s  %s%n",
                p.entry,
                p.score,
                p.insnCount,
                p.sizeBytes,
                String.join("|", sortStrings(p.tags)),
                p.name
            );
        }
        pw.close();
    }

    private void writeSuspect(File out, List<FunctionProfile> profiles, int suspectThreshold) throws Exception {
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        List<FunctionProfile> suspects = new ArrayList<>();
        for (FunctionProfile p : profiles) {
            if ("SUSPECT".equals(p.cls)) suspects.add(p);
        }
        suspects.sort(Comparator.comparingDouble((FunctionProfile p) -> p.score));

        pw.printf("Suspect Functions (threshold <= %d or hard fail)%n", suspectThreshold);
        pw.printf("Program: %s%n", currentProgram.getName());
        pw.printf("Count: %d%n%n", suspects.size());
        pw.println("Address       Score  Insns  Null%   OOR%   Reasons                          Name");
        pw.println("------------  -----  -----  ------  -----  -------------------------------  -----------------------------");

        for (FunctionProfile p : suspects) {
            pw.printf(
                Locale.ROOT,
                "%-12s  %5.1f  %5d  %6.1f  %5.1f  %-31s  %s%n",
                p.entry,
                p.score,
                p.insnCount,
                p.nullRatio * 100.0,
                p.outFlowRatio * 100.0,
                truncate(String.join("|", p.reasons), 31),
                p.name
            );
        }
        pw.close();
    }

    private void writeRecoveryMap(
        File out,
        List<FunctionProfile> profiles,
        boolean includeMediumSeeds,
        int mediumSeedMinScore,
        int minDenyRangeBytes
    ) throws Exception {
        if (out.getParentFile() != null && !out.getParentFile().exists()) {
            out.getParentFile().mkdirs();
        }

        List<long[]> allowRanges = new ArrayList<>();
        List<long[]> denyRanges = new ArrayList<>();
        List<FunctionProfile> seeds = new ArrayList<>();
        Set<Long> seedSet = new HashSet<>();

        for (FunctionProfile p : profiles) {
            boolean allow = "HIGH".equals(p.cls) || "MEDIUM".equals(p.cls);
            if (allow) {
                allowRanges.addAll(p.bodyRanges);
            }

            if ("SUSPECT".equals(p.cls)) {
                denyRanges.addAll(p.bodyRanges);
            }

            boolean isSeed = "HIGH".equals(p.cls);
            if (!isSeed && includeMediumSeeds && "MEDIUM".equals(p.cls) && p.score >= (double) mediumSeedMinScore) {
                isSeed = true;
            }
            long entry = p.entry.getOffset();
            if (isSeed && seedSet.add(Long.valueOf(entry))) {
                seeds.add(p);
            }
        }

        List<long[]> allowMerged = mergeRanges(allowRanges, 32, 4);
        List<long[]> denyMerged = mergeRanges(denyRanges, 16, Math.max(4, minDenyRangeBytes));
        denyMerged = subtractRanges(denyMerged, allowMerged);
        Collections.sort(seeds, Comparator.comparingLong((FunctionProfile p) -> p.entry.getOffset()));

        StringBuilder sb = new StringBuilder(128 * 1024);
        sb.append("{\n");
        sb.append("  \"meta\": {\n");
        sb.append("    \"name\": \"function-confidence-recovery-map\",\n");
        sb.append("    \"version\": \"1\",\n");
        sb.append("    \"program\": \"").append(jsonEscape(currentProgram.getName())).append("\",\n");
        sb.append("    \"source\": \"FunctionConfidenceProfile.java\",\n");
        sb.append("    \"include_medium_seeds\": ").append(includeMediumSeeds).append(",\n");
        sb.append("    \"medium_seed_min_score\": ").append(mediumSeedMinScore).append(",\n");
        sb.append("    \"seed_count\": ").append(seeds.size()).append(",\n");
        sb.append("    \"allow_ranges\": ").append(allowMerged.size()).append(",\n");
        sb.append("    \"deny_ranges\": ").append(denyMerged.size()).append("\n");
        sb.append("  },\n");

        sb.append("  \"allow_ranges\": [\n");
        for (int i = 0; i < allowMerged.size(); i++) {
            long[] r = allowMerged.get(i);
            sb.append("    {\"start\": \"").append(hex32(r[0])).append("\", \"end\": \"")
              .append(hex32(r[1])).append("\", \"name\": \"fn_conf_allow\"}");
            if (i + 1 < allowMerged.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"deny_ranges\": [\n");
        for (int i = 0; i < denyMerged.size(); i++) {
            long[] r = denyMerged.get(i);
            sb.append("    {\"start\": \"").append(hex32(r[0])).append("\", \"end\": \"")
              .append(hex32(r[1])).append("\", \"name\": \"fn_conf_deny\"}");
            if (i + 1 < denyMerged.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"seeds\": [\n");
        for (int i = 0; i < seeds.size(); i++) {
            FunctionProfile p = seeds.get(i);
            sb.append("    {\"addr\": \"").append(hex32(p.entry.getOffset())).append("\", ");
            sb.append("\"name\": \"").append(jsonEscape(p.name)).append("\", ");
            sb.append("\"create_function\": true}");
            if (i + 1 < seeds.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");

        PrintWriter pw = new PrintWriter(new FileWriter(out));
        pw.print(sb.toString());
        pw.close();
    }

    private static List<long[]> mergeRanges(List<long[]> ranges, int maxGapBytes, int minBytes) {
        List<long[]> out = new ArrayList<>();
        if (ranges.isEmpty()) return out;

        List<long[]> sorted = new ArrayList<>(ranges);
        sorted.sort(Comparator.comparingLong((long[] r) -> r[0]));

        long curStart = sorted.get(0)[0];
        long curEnd = sorted.get(0)[1];
        long maxGap = Math.max(0, maxGapBytes);
        long minLen = Math.max(1, minBytes);

        for (int i = 1; i < sorted.size(); i++) {
            long[] r = sorted.get(i);
            long start = r[0];
            long end = r[1];
            if (start <= curEnd + maxGap + 1) {
                if (end > curEnd) curEnd = end;
                continue;
            }

            if ((curEnd - curStart + 1) >= minLen) {
                out.add(new long[] { curStart, curEnd });
            }
            curStart = start;
            curEnd = end;
        }

        if ((curEnd - curStart + 1) >= minLen) {
            out.add(new long[] { curStart, curEnd });
        }
        return out;
    }

    private static List<long[]> subtractRanges(List<long[]> deny, List<long[]> allow) {
        List<long[]> result = new ArrayList<>();
        if (deny.isEmpty()) return result;
        if (allow.isEmpty()) {
            result.addAll(deny);
            return result;
        }

        List<long[]> sortedAllow = new ArrayList<>(allow);
        sortedAllow.sort(Comparator.comparingLong((long[] r) -> r[0]));

        for (long[] d : deny) {
            long start = d[0];
            long end = d[1];
            long cursor = start;

            for (long[] a : sortedAllow) {
                if (a[1] < cursor) continue;
                if (a[0] > end) break;

                if (a[0] > cursor) {
                    result.add(new long[] { cursor, a[0] - 1 });
                }
                if (a[1] + 1 > cursor) {
                    cursor = a[1] + 1;
                }
                if (cursor > end) break;
            }

            if (cursor <= end) {
                result.add(new long[] { cursor, end });
            }
        }
        return mergeRanges(result, 0, 1);
    }

    private static String hex32(long v) {
        return String.format(Locale.ROOT, "0x%08X", v & 0xFFFFFFFFL);
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static boolean isLoadMnemonic(String m) {
        return m.startsWith("ld") || m.startsWith("fld") || m.startsWith("pfld");
    }

    private static boolean isStoreMnemonic(String m) {
        return m.startsWith("st") || m.startsWith("fst") || m.startsWith("pfst");
    }

    private static boolean isFpMnemonic(String m) {
        return m.startsWith("f") || m.startsWith("pf") || m.startsWith("ixfr") || m.startsWith("fxfr");
    }

    private static boolean hasDelaySlot(int word) {
        int op6 = (word >>> 26) & 0x3F;
        if (op6 == 0x1A || op6 == 0x1B || op6 == 0x1D || op6 == 0x1F || op6 == 0x2D || op6 == 0x10) {
            return true;
        }
        if (op6 == 0x13) {
            int escop = word & 0x7;
            return escop == 0x2; // calli
        }
        return false;
    }

    private static boolean isReturnInstruction(Instruction insn, int word) {
        String mnemonic = insn.getMnemonicString();
        if ("ret".equals(mnemonic) || "_ret".equals(mnemonic)) return true;
        if (!"bri".equals(mnemonic) && !"_bri".equals(mnemonic)) return false;
        int op6 = (word >>> 26) & 0x3F;
        int src1 = (word >>> 11) & 0x1F;
        return op6 == 0x10 && src1 == 1;
    }

    // Heuristic: clean-firmware PostScript prolog and symbol tables tend to live
    // in 0x0000F800-0x0000FFFF and mapped variants around 0xF800F800-0xF800FFFF.
    private static boolean isLikelyPostScriptRef(long u32) {
        if (u32 >= 0x0000F800L && u32 <= 0x0000FFFFL) return true;
        if (u32 >= 0xF800F800L && u32 <= 0xF800FFFFL) return true;
        return false;
    }

    private static Integer readWord(Memory memory, Address addr) {
        try {
            return Integer.valueOf(memory.getInt(addr));
        } catch (Exception e) {
            return null;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, Math.max(0, max - 1)) + "~";
    }

    private static List<String> sortStrings(Set<String> set) {
        List<String> out = new ArrayList<>(set);
        Collections.sort(out);
        return out;
    }

    private static String csvEscape(String s) {
        if (s == null) return "";
        String v = s.replace("\"", "\"\"");
        if (v.contains(",") || v.contains("\"") || v.contains("\n")) {
            return "\"" + v + "\"";
        }
        return v;
    }

    private static int parseIntArg(String[] args, int idx, int fallback) {
        if (args.length <= idx) return fallback;
        String s = args[idx] == null ? "" : args[idx].trim();
        if (s.isEmpty()) return fallback;
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return fallback;
        }
    }

    private static boolean parseBooleanArg(String[] args, int idx, boolean fallback) {
        if (args.length <= idx) return fallback;
        String s = args[idx] == null ? "" : args[idx].trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty()) return fallback;
        if ("1".equals(s) || "true".equals(s) || "yes".equals(s) || "y".equals(s)) return true;
        if ("0".equals(s) || "false".equals(s) || "no".equals(s) || "n".equals(s)) return false;
        return fallback;
    }

    private static String parseStringArg(String[] args, int idx, String fallback) {
        if (args.length <= idx) return fallback;
        String s = args[idx] == null ? "" : args[idx].trim();
        return s.isEmpty() ? fallback : s;
    }
}
