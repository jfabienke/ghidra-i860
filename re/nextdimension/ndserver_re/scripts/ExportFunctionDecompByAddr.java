// Decompile selected functions by entry/function-containing address list.
//
// Usage (postScript):
//   ExportFunctionDecompByAddr.java --out=<path> --func=0x7000621e,0x70002ea0 [--timeout=60]
//
// @category m68k

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportFunctionDecompByAddr extends GhidraScript {

    private String outPath;
    private int timeoutSec = 60;
    private List<Long> funcAddrs = new ArrayList<>();

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());
        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_func_decomp_by_addr.txt";
        }
        if (funcAddrs.isEmpty()) {
            printerr("missing --func=<hex,hex,...>");
            return;
        }

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refm = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# Function Decomp By Address\n\n");
            w.write("generated_at_utc: " + Instant.now().toString() + "\n");
            w.write("program_name: " + currentProgram.getName() + "\n");
            w.write("language_id: " + currentProgram.getLanguageID().getIdAsString() + "\n\n");

            int idx = 1;
            for (Long raw : funcAddrs) {
                if (monitor.isCancelled()) break;
                Address addr = toAddr(raw);
                Function f = fm.getFunctionAt(addr);
                if (f == null) {
                    f = fm.getFunctionContaining(addr);
                }

                w.write("===============================================================================\n");
                w.write(String.format("%2d. requested=%s (%s)\n", idx, addr, hex(raw)));
                if (f == null) {
                    w.write("function: (not found)\n\n");
                    idx++;
                    continue;
                }

                w.write("function: " + f.getName() + " @ " + f.getEntryPoint() +
                    " size=" + f.getBody().getNumAddresses() + "\n\n");

                Set<String> callers = new LinkedHashSet<>();
                ReferenceIterator rit = refm.getReferencesTo(f.getEntryPoint());
                while (rit.hasNext()) {
                    Reference r = rit.next();
                    if (!r.getReferenceType().isCall()) continue;
                    Function cf = fm.getFunctionContaining(r.getFromAddress());
                    if (cf == null) callers.add("<no-func> @ " + r.getFromAddress());
                    else callers.add(cf.getName() + " @ " + cf.getEntryPoint() + " -> " + r.getFromAddress());
                }

                Set<String> callees = new LinkedHashSet<>();
                InstructionIterator iit = listing.getInstructions(f.getBody(), true);
                while (iit.hasNext()) {
                    Instruction insn = iit.next();
                    if (insn.getFlowType() == null || !insn.getFlowType().isCall()) continue;
                    if (insn.getFlows() == null || insn.getFlows().length == 0) {
                        callees.add(insn.getAddress() + " -> <indirect>");
                        continue;
                    }
                    for (Address to : insn.getFlows()) {
                        Function tf = fm.getFunctionAt(to);
                        if (tf == null) tf = fm.getFunctionContaining(to);
                        if (tf == null) callees.add(insn.getAddress() + " -> " + to);
                        else callees.add(insn.getAddress() + " -> " + tf.getName() + " @ " + tf.getEntryPoint());
                    }
                }

                w.write("Callers:\n");
                if (callers.isEmpty()) w.write("- (none)\n");
                else for (String s : callers) w.write("- " + s + "\n");
                w.write("\n");

                w.write("Callees:\n");
                if (callees.isEmpty()) w.write("- (none)\n");
                else for (String s : callees) w.write("- " + s + "\n");
                w.write("\n");

                DecompileResults dr = di.decompileFunction(f, timeoutSec, monitor);
                w.write("Decompiled C:\n\n");
                if (dr == null || !dr.decompileCompleted() || dr.getDecompiledFunction() == null) {
                    String err = (dr == null) ? "null results" : dr.getErrorMessage();
                    w.write("[decompilation failed] " + sanitize(err) + "\n\n");
                }
                else {
                    w.write("```c\n");
                    w.write(dr.getDecompiledFunction().getC());
                    w.write("\n```\n\n");
                }
                idx++;
            }
        }
        finally {
            di.dispose();
        }

        println("Exported function decomp-by-addr report to: " + p.toAbsolutePath());
    }

    private String hex(long v) {
        return String.format("0x%08x", v);
    }

    private String sanitize(String s) {
        if (s == null) return "";
        String t = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
        if (t.length() > 240) return t.substring(0, 237) + "...";
        return t;
    }

    private void parseArgs(String[] args) {
        if (args == null) return;
        for (String raw : args) {
            if (raw == null) continue;
            String a = raw.trim();
            if (a.startsWith("--out=")) {
                outPath = a.substring("--out=".length()).trim();
            }
            else if (a.startsWith("--timeout=")) {
                try {
                    int n = Integer.parseInt(a.substring("--timeout=".length()).trim());
                    if (n > 0) timeoutSec = n;
                }
                catch (NumberFormatException ignored) {}
            }
            else if (a.startsWith("--func=")) {
                String body = a.substring("--func=".length()).trim();
                for (String part : body.split(",")) {
                    Long v = parseU32(part.trim());
                    if (v != null) funcAddrs.add(v);
                }
            }
        }
    }

    private Long parseU32(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        String t = raw.toLowerCase();
        if (t.startsWith("0x")) t = t.substring(2);
        try {
            return Long.parseUnsignedLong(t, 16);
        }
        catch (Exception ex) {
            return null;
        }
    }
}
