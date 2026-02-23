// Decompile m68k functions selected via ND-related string xrefs.
//
// Usage (postScript):
//   ExportM68kInterestingDecomp.java --out=<path> [--max=N] [--timeout=sec]
//
// @category m68k

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportM68kInterestingDecomp extends GhidraScript {

    private static class Candidate {
        Function function;
        Set<String> reasons;
        long bodySize;

        Candidate(Function function, Set<String> reasons, long bodySize) {
            this.function = function;
            this.reasons = reasons;
            this.bodySize = bodySize;
        }
    }

    private String outPath;
    private int maxFunctions = 20;
    private int timeoutSec = 45;

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());

        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_m68k_interesting_decomp.txt";
        }

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refm = currentProgram.getReferenceManager();

        Map<Function, LinkedHashSet<String>> reasonMap = new HashMap<>();

        DataIterator dit = listing.getDefinedData(true);
        while (dit.hasNext() && !monitor.isCancelled()) {
            Data d = dit.next();
            if (d == null) continue;

            String s = extractString(d);
            if (s == null || s.isEmpty()) continue;
            if (!isInterestingString(s)) continue;

            ReferenceIterator rit = refm.getReferencesTo(d.getAddress());
            while (rit.hasNext()) {
                Reference r = rit.next();
                Function f = fm.getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                LinkedHashSet<String> rs = reasonMap.get(f);
                if (rs == null) {
                    rs = new LinkedHashSet<>();
                    reasonMap.put(f, rs);
                }
                rs.add(s);
            }
        }

        List<Candidate> candidates = new ArrayList<>();
        for (Map.Entry<Function, LinkedHashSet<String>> e : reasonMap.entrySet()) {
            Function f = e.getKey();
            long body = f.getBody().getNumAddresses();
            candidates.add(new Candidate(f, e.getValue(), body));
        }

        Collections.sort(candidates, new Comparator<Candidate>() {
            @Override
            public int compare(Candidate a, Candidate b) {
                int cmp = Integer.compare(b.reasons.size(), a.reasons.size());
                if (cmp != 0) return cmp;
                cmp = Long.compare(b.bodySize, a.bodySize);
                if (cmp != 0) return cmp;
                return a.function.getEntryPoint().compareTo(b.function.getEntryPoint());
            }
        });

        if (candidates.size() > maxFunctions) {
            candidates = new ArrayList<>(candidates.subList(0, maxFunctions));
        }

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# M68k ND Interesting Decomp\n\n");
            w.write("generated_at_utc: " + Instant.now().toString() + "\n");
            w.write("program_name: " + currentProgram.getName() + "\n");
            w.write("executable_path: " + currentProgram.getExecutablePath() + "\n");
            w.write("language_id: " + currentProgram.getLanguageID().getIdAsString() + "\n");
            w.write("candidate_function_count: " + candidates.size() + "\n\n");

            int idx = 1;
            for (Candidate c : candidates) {
                if (monitor.isCancelled()) break;

                Function f = c.function;
                Address ep = f.getEntryPoint();

                w.write("===============================================================================\n");
                w.write(String.format("%2d. %s @ %s size=%d reason_count=%d\n",
                    idx, f.getName(), ep.toString(), c.bodySize, c.reasons.size()));
                w.write("Reasons:\n");
                int rcount = 0;
                for (String reason : c.reasons) {
                    w.write("  - \"" + sanitize(reason) + "\"\n");
                    rcount++;
                    if (rcount >= 12) {
                        w.write("  - ...\n");
                        break;
                    }
                }

                List<String> callers = getCallers(f, refm, fm);
                List<String> callees = getCallees(f, listing, fm);

                w.write("Callers:\n");
                if (callers.isEmpty()) {
                    w.write("  - (none)\n");
                }
                else {
                    for (String s : callers) {
                        w.write("  - " + s + "\n");
                    }
                }

                w.write("Callees:\n");
                if (callees.isEmpty()) {
                    w.write("  - (none)\n");
                }
                else {
                    int lim = Math.min(30, callees.size());
                    for (int i = 0; i < lim; i++) {
                        w.write("  - " + callees.get(i) + "\n");
                    }
                    if (callees.size() > lim) {
                        w.write("  - ...\n");
                    }
                }

                DecompileResults dr = decomp.decompileFunction(f, timeoutSec, monitor);
                if (dr == null || !dr.decompileCompleted() || dr.getDecompiledFunction() == null) {
                    String err = (dr == null) ? "null results" : dr.getErrorMessage();
                    w.write("\n[decompilation failed] " + sanitize(err) + "\n\n");
                }
                else {
                    String cText = dr.getDecompiledFunction().getC();
                    w.write("\nDecompiled C:\n\n");
                    w.write(cText);
                    w.write("\n\n");
                }

                idx++;
            }
        }

        decomp.dispose();
        println("Exported ND m68k decomp report to: " + p.toAbsolutePath());
    }

    private List<String> getCallers(Function f, ReferenceManager refm, FunctionManager fm) {
        Set<String> out = new LinkedHashSet<>();
        ReferenceIterator rit = refm.getReferencesTo(f.getEntryPoint());
        while (rit.hasNext()) {
            Reference r = rit.next();
            if (!r.getReferenceType().isCall()) continue;
            Function caller = fm.getFunctionContaining(r.getFromAddress());
            if (caller != null) {
                out.add(caller.getName() + " @ " + caller.getEntryPoint() + " -> " + r.getFromAddress());
            }
            else {
                out.add("<no-func> @ " + r.getFromAddress());
            }
        }
        return new ArrayList<>(out);
    }

    private List<String> getCallees(Function f, Listing listing, FunctionManager fm) {
        Set<String> out = new LinkedHashSet<>();
        InstructionIterator iit = listing.getInstructions(f.getBody(), true);
        while (iit.hasNext()) {
            Instruction insn = iit.next();
            FlowType ft = insn.getFlowType();
            if (ft == null || !ft.isCall()) continue;

            Address[] flows = insn.getFlows();
            if (flows == null || flows.length == 0) {
                out.add(insn.getAddress() + " -> <indirect>");
                continue;
            }

            for (Address to : flows) {
                Function callee = fm.getFunctionAt(to);
                if (callee == null) {
                    callee = fm.getFunctionContaining(to);
                }
                if (callee != null) {
                    out.add(insn.getAddress() + " -> " + callee.getName() + " @ " + callee.getEntryPoint());
                }
                else {
                    out.add(insn.getAddress() + " -> " + to);
                }
            }
        }
        return new ArrayList<>(out);
    }

    private void parseArgs(String[] args) {
        if (args == null) return;
        for (String raw : args) {
            if (raw == null) continue;
            String a = raw.trim();
            if (a.isEmpty()) continue;
            if (a.startsWith("--out=")) {
                outPath = a.substring("--out=".length()).trim();
            }
            else if (a.startsWith("--max=")) {
                String v = a.substring("--max=".length()).trim();
                try {
                    int n = Integer.parseInt(v);
                    if (n > 0) maxFunctions = n;
                }
                catch (NumberFormatException ignored) {}
            }
            else if (a.startsWith("--timeout=")) {
                String v = a.substring("--timeout=".length()).trim();
                try {
                    int n = Integer.parseInt(v);
                    if (n > 0) timeoutSec = n;
                }
                catch (NumberFormatException ignored) {}
            }
        }
    }

    private String extractString(Data d) {
        try {
            Object v = d.getValue();
            if (v instanceof String) {
                return (String) v;
            }
        }
        catch (Exception ignored) {}

        try {
            if (d.hasStringValue()) {
                String rep = d.getDefaultValueRepresentation();
                if (rep != null) return rep;
            }
        }
        catch (Exception ignored) {}

        return null;
    }

    private boolean isInterestingString(String s) {
        String ls = s.toLowerCase();
        String[] keys = new String[] {
            "nextdimension",
            "ndserver",
            "nd_machdriver",
            "nddriver",
            "nd_",
            "kern_loader",
            "windowserver",
            "postscript",
            "port_",
            "msg_",
            "display",
            "psdrvr"
        };
        for (String k : keys) {
            if (ls.contains(k)) return true;
        }
        return false;
    }

    private String sanitize(String s) {
        if (s == null) return "";
        String t = s.replace("\\", "\\\\");
        t = t.replace("\n", "\\n");
        t = t.replace("\r", "\\r");
        t = t.replace("\t", "\\t");
        t = t.replace("\"", "\\\"");
        if (t.length() > 220) {
            return t.substring(0, 217) + "...";
        }
        return t;
    }
}
