// Export a concise m68k-focused analysis summary for NDserver-like binaries.
//
// Usage (postScript):
//   ExportM68kSummary.java --out=<path> [--top=N]
//
// @category m68k

import ghidra.app.script.GhidraScript;
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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportM68kSummary extends GhidraScript {

    private static class FunctionInfo {
        String name;
        Address entry;
        long bodySize;
        int instructionCount;

        FunctionInfo(String name, Address entry, long bodySize, int instructionCount) {
            this.name = name;
            this.entry = entry;
            this.bodySize = bodySize;
            this.instructionCount = instructionCount;
        }
    }

    private static class StringInfo {
        Address addr;
        String value;
        int refCount;
        Set<String> refFunctions;

        StringInfo(Address addr, String value, int refCount, Set<String> refFunctions) {
            this.addr = addr;
            this.value = value;
            this.refCount = refCount;
            this.refFunctions = refFunctions;
        }
    }

    private String outPath;
    private int topN = 25;

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());

        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_m68k_summary.txt";
        }

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable symtab = currentProgram.getSymbolTable();
        ReferenceManager refm = currentProgram.getReferenceManager();
        ExternalManager extm = currentProgram.getExternalManager();

        long functionTotal = 0;
        long functionExternal = 0;
        long functionThunk = 0;

        List<FunctionInfo> funcs = new ArrayList<>();

        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            functionTotal++;
            if (f.isExternal()) {
                functionExternal++;
            }
            if (f.isThunk()) {
                functionThunk++;
            }

            AddressSetView body = f.getBody();
            long bodySize = body.getNumAddresses();
            int insnCount = 0;

            InstructionIterator iit = listing.getInstructions(body, true);
            while (iit.hasNext()) {
                iit.next();
                insnCount++;
            }

            funcs.add(new FunctionInfo(f.getName(), f.getEntryPoint(), bodySize, insnCount));
        }

        Collections.sort(funcs, new Comparator<FunctionInfo>() {
            @Override
            public int compare(FunctionInfo a, FunctionInfo b) {
                int cmp = Long.compare(b.bodySize, a.bodySize);
                if (cmp != 0) return cmp;
                return a.entry.compareTo(b.entry);
            }
        });

        long insnTotal = 0;
        long callInsn = 0;
        long jumpInsn = 0;
        long termInsn = 0;

        InstructionIterator allInsns = listing.getInstructions(true);
        while (allInsns.hasNext() && !monitor.isCancelled()) {
            Instruction insn = allInsns.next();
            insnTotal++;
            FlowType ft = insn.getFlowType();
            if (ft != null) {
                if (ft.isCall()) callInsn++;
                if (ft.isJump()) jumpInsn++;
                if (ft.isTerminal()) termInsn++;
            }
        }

        List<String> entryPoints = new ArrayList<>();
        AddressIterator eiter = symtab.getExternalEntryPointIterator();
        while (eiter.hasNext() && !monitor.isCancelled()) {
            Address a = eiter.next();
            Symbol s = symtab.getPrimarySymbol(a);
            String name = (s != null) ? s.getName() : "<no-symbol>";
            entryPoints.add(a.toString() + " " + name);
        }

        String[] libraries = extm.getExternalLibraryNames();
        List<String> libs = new ArrayList<>();
        if (libraries != null) {
            for (String lib : libraries) {
                if (lib != null && !lib.trim().isEmpty()) {
                    libs.add(lib);
                }
            }
            Collections.sort(libs);
        }

        int allStringCount = 0;
        List<StringInfo> interestingStrings = new ArrayList<>();

        DataIterator dit = listing.getDefinedData(true);
        while (dit.hasNext() && !monitor.isCancelled()) {
            Data d = dit.next();
            if (d == null) continue;

            String s = extractString(d);
            if (s == null || s.isEmpty()) continue;

            allStringCount++;
            if (!isInterestingString(s)) continue;

            int refCount = 0;
            Set<String> refFuncs = new LinkedHashSet<>();

            ReferenceIterator rit = refm.getReferencesTo(d.getAddress());
            while (rit.hasNext()) {
                Reference r = rit.next();
                refCount++;
                Function rf = fm.getFunctionContaining(r.getFromAddress());
                if (rf != null) {
                    refFuncs.add(rf.getName());
                }
            }

            interestingStrings.add(new StringInfo(d.getAddress(), s, refCount, refFuncs));
        }

        Collections.sort(interestingStrings, new Comparator<StringInfo>() {
            @Override
            public int compare(StringInfo a, StringInfo b) {
                int cmp = Integer.compare(b.refCount, a.refCount);
                if (cmp != 0) return cmp;
                return a.addr.compareTo(b.addr);
            }
        });

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# M68k Ghidra Summary\n\n");
            w.write("generated_at_utc: " + Instant.now().toString() + "\n");
            w.write("program_name: " + currentProgram.getName() + "\n");
            w.write("executable_path: " + currentProgram.getExecutablePath() + "\n");
            w.write("language_id: " + currentProgram.getLanguageID().getIdAsString() + "\n");
            w.write("compiler_spec: " + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString() + "\n");
            w.write("image_base: " + currentProgram.getImageBase().toString() + "\n\n");

            w.write("## Function Stats\n\n");
            w.write("function_total: " + functionTotal + "\n");
            w.write("function_external: " + functionExternal + "\n");
            w.write("function_thunk: " + functionThunk + "\n\n");

            w.write("## Instruction Stats\n\n");
            w.write("instruction_total: " + insnTotal + "\n");
            w.write("call_instructions: " + callInsn + "\n");
            w.write("jump_instructions: " + jumpInsn + "\n");
            w.write("terminal_instructions: " + termInsn + "\n\n");

            w.write("## Entry Points\n\n");
            if (entryPoints.isEmpty()) {
                w.write("(none)\n\n");
            }
            else {
                for (String ep : entryPoints) {
                    w.write("- " + ep + "\n");
                }
                w.write("\n");
            }

            w.write("## External Libraries\n\n");
            if (libs.isEmpty()) {
                w.write("(none)\n\n");
            }
            else {
                for (String lib : libs) {
                    w.write("- " + lib + "\n");
                }
                w.write("\n");
            }

            w.write("## Top Functions By Body Size\n\n");
            int limit = Math.min(topN, funcs.size());
            for (int i = 0; i < limit; i++) {
                FunctionInfo fi = funcs.get(i);
                w.write(String.format("%3d. %s @ %s size=%d insn=%d\n",
                    i + 1,
                    fi.name,
                    fi.entry.toString(),
                    fi.bodySize,
                    fi.instructionCount));
            }
            w.write("\n");

            w.write("## String Stats\n\n");
            w.write("defined_strings_total: " + allStringCount + "\n");
            w.write("interesting_strings_total: " + interestingStrings.size() + "\n\n");

            w.write("## Interesting Strings\n\n");
            int stringLimit = Math.min(150, interestingStrings.size());
            for (int i = 0; i < stringLimit; i++) {
                StringInfo si = interestingStrings.get(i);
                w.write("- " + si.addr + " refs=" + si.refCount + " value=\"" + sanitize(si.value) + "\"\n");
                if (!si.refFunctions.isEmpty()) {
                    int c = 0;
                    StringBuilder sb = new StringBuilder();
                    sb.append("  functions: ");
                    for (String fn : si.refFunctions) {
                        if (c > 0) sb.append(", ");
                        sb.append(fn);
                        c++;
                        if (c >= 15) {
                            sb.append(", ...");
                            break;
                        }
                    }
                    w.write(sb.toString() + "\n");
                }
            }
        }

        println("Exported m68k summary to: " + p.toAbsolutePath());
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
            else if (a.startsWith("--top=")) {
                String v = a.substring("--top=".length()).trim();
                try {
                    int n = Integer.parseInt(v);
                    if (n > 0) topN = n;
                }
                catch (NumberFormatException ignored) {
                }
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
        catch (Exception ignored) {
        }

        try {
            if (d.hasStringValue()) {
                String rep = d.getDefaultValueRepresentation();
                if (rep != null) {
                    return rep;
                }
            }
        }
        catch (Exception ignored) {
        }

        return null;
    }

    private boolean isInterestingString(String s) {
        String ls = s.toLowerCase();

        String[] keys = new String[] {
            "nextdimension",
            "ndserver",
            "nd_machdriver",
            "nd_",
            "kern_loader",
            "windowserver",
            "postscript",
            "mach",
            "port_",
            "msg_",
            "driver",
            "display",
            "psdrvr"
        };

        for (String k : keys) {
            if (ls.contains(k)) {
                return true;
            }
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

        if (t.length() > 260) {
            return t.substring(0, 257) + "...";
        }
        return t;
    }
}
