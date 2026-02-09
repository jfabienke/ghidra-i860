// Decompile a selection of kernel functions and print C output.
// Used to evaluate decompiler quality on i860 code.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecompileSample extends GhidraScript {

    private static final Pattern UNAFF_PATTERN = Pattern.compile("\\bunaff_[A-Za-z0-9_]+\\b");

    private static class SampleTarget {
        final Function function;
        final String reason;
        final long sizeBytes;
        final String firstInsn;

        SampleTarget(Function function, String reason, long sizeBytes, String firstInsn) {
            this.function = function;
            this.reason = reason;
            this.sizeBytes = sizeBytes;
            this.firstInsn = firstInsn;
        }
    }

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Listing listing = currentProgram.getListing();
        int sampleCount = Integer.getInteger("ghidra.decompile.sample.count", 12);
        int timeoutSec = Integer.getInteger("ghidra.decompile.timeout", 30);
        List<SampleTarget> targets = selectTargets(listing, sampleCount);

        StringBuilder sb = new StringBuilder();
        sb.append("=== i860 Kernel Decompiler Quality Check ===\n\n");
        sb.append(String.format("Selected %d target functions (requested %d)\n\n",
            targets.size(), sampleCount));

        int success = 0;
        int failed = 0;
        int timeout = 0;

        int totalBadData = 0;
        int totalUnimpl = 0;
        int totalUnaff = 0;
        int totalUnreachable = 0;
        int totalJumptable = 0;

        int funcsWithBadData = 0;
        int funcsWithUnimpl = 0;
        int funcsWithUnaff = 0;
        int funcsWithUnreachable = 0;
        int funcsWithJumptable = 0;

        for (SampleTarget target : targets) {
            if (monitor.isCancelled()) break;

            Function func = target.function;
            Address addr = func.getEntryPoint();

            sb.append(String.format("════════════════════════════════════════════════════════════════\n"));
            sb.append(String.format("  %s (%d bytes)\n", func.getName(), target.sizeBytes));
            sb.append(String.format("  @ %s  [%s]\n", addr, target.reason));
            sb.append(String.format("  first: %s\n", target.firstInsn));
            sb.append(String.format("════════════════════════════════════════════════════════════════\n\n"));

            DecompileResults results = decomp.decompileFunction(func, timeoutSec, monitor);

            if (results == null || !results.decompileCompleted()) {
                String err = results != null ? results.getErrorMessage() : "null result";
                sb.append(String.format("  [decompilation failed: %s]\n\n", err));
                if (err != null && err.toLowerCase(Locale.ROOT).contains("time")) {
                    timeout++;
                }
                failed++;
                continue;
            }

            DecompiledFunction dfunc = results.getDecompiledFunction();
            if (dfunc == null) {
                sb.append("  [no decompiled function returned]\n\n");
                failed++;
                continue;
            }

            String c = dfunc.getC();
            int badDataCount = countOccurrences(c, "halt_baddata()");
            int unimplCount = countOccurrences(c, "halt_unimplemented()");
            int unaffCount = countPatternMatches(UNAFF_PATTERN, c);
            int unreachableCount = countOccurrences(c, "Removing unreachable block");
            int jumptableCount = countOccurrences(c, "Could not recover jumptable");

            totalBadData += badDataCount;
            totalUnimpl += unimplCount;
            totalUnaff += unaffCount;
            totalUnreachable += unreachableCount;
            totalJumptable += jumptableCount;

            if (badDataCount > 0) funcsWithBadData++;
            if (unimplCount > 0) funcsWithUnimpl++;
            if (unaffCount > 0) funcsWithUnaff++;
            if (unreachableCount > 0) funcsWithUnreachable++;
            if (jumptableCount > 0) funcsWithJumptable++;

            sb.append(String.format(
                "  KPI: halt_baddata=%d, halt_unimplemented=%d, unaff=%d, unreachable=%d, unrecovered_jumptable=%d\n\n",
                badDataCount, unimplCount, unaffCount, unreachableCount, jumptableCount));
            sb.append(c);
            sb.append("\n");
            success++;
        }

        sb.append(String.format("════════════════════════════════════════════════════════════════\n"));
        sb.append(String.format("  Summary: %d/%d functions decompiled successfully\n",
                  success, success + failed));
        sb.append(String.format("  Timeouts: %d\n", timeout));
        sb.append("\n");
        sb.append("  Aggregate KPIs\n");
        sb.append(String.format("    halt_baddata(): %d across %d/%d successful decompilations\n",
            totalBadData, funcsWithBadData, success));
        sb.append(String.format("    halt_unimplemented(): %d across %d/%d successful decompilations\n",
            totalUnimpl, funcsWithUnimpl, success));
        sb.append(String.format("    unaff_* variables: %d across %d/%d successful decompilations\n",
            totalUnaff, funcsWithUnaff, success));
        sb.append(String.format("    Unreachable block warnings: %d across %d/%d successful decompilations\n",
            totalUnreachable, funcsWithUnreachable, success));
        sb.append(String.format("    Unrecovered jumptable warnings: %d across %d/%d successful decompilations\n",
            totalJumptable, funcsWithJumptable, success));
        sb.append(String.format("════════════════════════════════════════════════════════════════\n"));

        String output = sb.toString();
        printf("%s", output);

        // Write to file
        String outPath = System.getProperty("ghidra.decompile.output",
            "/tmp/i860_kernel_decompile.txt");
        java.io.PrintWriter pw = new java.io.PrintWriter(new java.io.FileWriter(outPath));
        pw.print(output);
        pw.close();
        printf("\nWritten to: %s\n", outPath);

        decomp.dispose();
    }

    private List<SampleTarget> selectTargets(Listing listing, int maxTargets) {
        List<Function> all = new ArrayList<>();
        Function entry = null;
        FunctionIterator fi = listing.getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            if ("entry".equals(f.getName())) {
                entry = f;
            }
            all.add(f);
        }

        List<Function> viable = new ArrayList<>();
        List<Function> prologue = new ArrayList<>();
        List<Function> branchHeavy = new ArrayList<>();
        List<Function> fpHeavy = new ArrayList<>();

        for (Function f : all) {
            if (!isViableFunction(listing, f)) continue;
            viable.add(f);
            String mnem = firstMnemonic(listing, f).toLowerCase(Locale.ROOT);
            if (mnem.startsWith("subs") || mnem.startsWith("addu")) {
                prologue.add(f);
            }
            if (mnem.startsWith("b") || mnem.contains("call")) {
                branchHeavy.add(f);
            }
            if (mnem.startsWith("f") || mnem.contains("fld") || mnem.contains("fst") || mnem.contains("pf")) {
                fpHeavy.add(f);
            }
        }

        sortBySizeDesc(viable);
        sortBySizeDesc(prologue);
        sortBySizeDesc(branchHeavy);
        sortBySizeDesc(fpHeavy);

        LinkedHashMap<Long, SampleTarget> selected = new LinkedHashMap<>();
        if (entry != null && isViableFunction(listing, entry)) {
            putTarget(selected, listing, entry, "entry");
        }
        addFromList(selected, listing, viable, "largest", 3, maxTargets);
        addFromList(selected, listing, prologue, "prologue-like", 3, maxTargets);
        addFromList(selected, listing, branchHeavy, "branch-heavy", 2, maxTargets);
        addFromList(selected, listing, fpHeavy, "fp-heavy", 2, maxTargets);
        addFromList(selected, listing, viable, "fill", Integer.MAX_VALUE, maxTargets);

        return new ArrayList<>(selected.values());
    }

    private boolean isViableFunction(Listing listing, Function f) {
        if (f == null) return false;
        String name = f.getName();
        if (name != null && name.startsWith("data_")) return false;
        long size = functionSizeBytes(f);
        if (size < 8) return false;
        Instruction first = listing.getInstructionAt(f.getEntryPoint());
        return first != null;
    }

    private static long functionSizeBytes(Function f) {
        // i860 code is 32-bit fixed-width, and function bodies here are contiguous byte ranges.
        return f.getBody().getNumAddresses();
    }

    private String firstMnemonic(Listing listing, Function f) {
        Instruction first = listing.getInstructionAt(f.getEntryPoint());
        return first != null ? first.getMnemonicString() : "?";
    }

    private String firstInstructionString(Listing listing, Function f) {
        Instruction first = listing.getInstructionAt(f.getEntryPoint());
        return first != null ? first.toString() : "?";
    }

    private void addFromList(
        LinkedHashMap<Long, SampleTarget> selected,
        Listing listing,
        List<Function> src,
        String reason,
        int limit,
        int maxTargets
    ) {
        int added = 0;
        for (Function f : src) {
            if (selected.size() >= maxTargets) return;
            if (added >= limit) return;
            if (putTarget(selected, listing, f, reason)) {
                added++;
            }
        }
    }

    private boolean putTarget(
        LinkedHashMap<Long, SampleTarget> selected,
        Listing listing,
        Function f,
        String reason
    ) {
        long key = f.getEntryPoint().getOffset();
        if (selected.containsKey(key)) return false;
        SampleTarget target = new SampleTarget(
            f,
            reason,
            functionSizeBytes(f),
            firstInstructionString(listing, f)
        );
        selected.put(key, target);
        return true;
    }

    private void sortBySizeDesc(List<Function> funcs) {
        Collections.sort(funcs, new Comparator<Function>() {
            @Override
            public int compare(Function a, Function b) {
                long sa = functionSizeBytes(a);
                long sb = functionSizeBytes(b);
                if (sa == sb) return 0;
                return sa < sb ? 1 : -1;
            }
        });
    }

    private int countOccurrences(String text, String needle) {
        if (text == null || text.isEmpty() || needle == null || needle.isEmpty()) return 0;
        int count = 0;
        int idx = 0;
        while (true) {
            idx = text.indexOf(needle, idx);
            if (idx < 0) break;
            count++;
            idx += needle.length();
        }
        return count;
    }

    private int countPatternMatches(Pattern p, String text) {
        if (text == null || text.isEmpty()) return 0;
        int count = 0;
        Matcher m = p.matcher(text);
        while (m.find()) {
            count++;
        }
        return count;
    }
}
