// Scan all functions' decompiled C text for token substrings.
//
// Usage:
//   ScanDecompForTokens.java --out=<path> --tokens=t1,t2,t3 [--timeout=30]
//
// @category m68k

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ScanDecompForTokens extends GhidraScript {

    private String outPath;
    private int timeoutSeconds = 30;
    private List<String> tokens = new ArrayList<>();

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());

        if (tokens.isEmpty()) {
            println("No tokens configured; use --tokens=a,b,c");
            return;
        }
        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_token_scan.txt";
        }

        DecompInterface ifc = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        ifc.setOptions(options);
        ifc.openProgram(currentProgram);

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        int total = 0;
        int matched = 0;

        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# Scan Decomp For Tokens\n\n");
            w.write("generated_at_utc: " + Instant.now().toString() + "\n");
            w.write("program_name: " + currentProgram.getName() + "\n");
            w.write("language_id: " + currentProgram.getLanguageID().getIdAsString() + "\n");
            w.write("tokens: " + String.join(", ", tokens) + "\n\n");

            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal()) {
                    continue;
                }
                total++;

                DecompileResults res = ifc.decompileFunction(f, timeoutSeconds, monitor);
                if (!res.decompileCompleted() || res.getDecompiledFunction() == null) {
                    continue;
                }

                String c = res.getDecompiledFunction().getC();
                if (c == null || c.isEmpty()) {
                    continue;
                }

                List<String> hits = new ArrayList<>();
                for (String t : tokens) {
                    if (c.contains(t)) {
                        hits.add(t);
                    }
                }
                if (hits.isEmpty()) {
                    continue;
                }

                matched++;
                w.write("-------------------------------------------------------------------------------\n");
                w.write("function: " + f.getName() + " @ " + f.getEntryPoint().toString()
                    + " size=" + f.getBody().getNumAddresses() + "\n");
                w.write("hits: " + String.join(", ", hits) + "\n");
            }

            w.write("\nsummary: decompiled_functions=" + total + " matched_functions=" + matched + "\n");
        }

        ifc.dispose();
        println("Exported token scan to: " + p.toAbsolutePath());
    }

    private void parseArgs(String[] args) {
        if (args == null) {
            return;
        }
        for (String raw : args) {
            if (raw == null) {
                continue;
            }
            String a = raw.trim();
            if (a.startsWith("--out=")) {
                outPath = a.substring("--out=".length()).trim();
            }
            else if (a.startsWith("--tokens=")) {
                String v = a.substring("--tokens=".length()).trim();
                if (!v.isEmpty()) {
                    tokens = new ArrayList<>(Arrays.asList(v.split(",")));
                }
            }
            else if (a.startsWith("--timeout=")) {
                String v = a.substring("--timeout=".length()).trim();
                try {
                    int t = Integer.parseInt(v);
                    if (t > 0) {
                        timeoutSeconds = t;
                    }
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
    }
}
