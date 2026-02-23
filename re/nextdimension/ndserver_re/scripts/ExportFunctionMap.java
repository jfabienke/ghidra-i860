// Export all discovered functions with size and simple metrics.
//
// Usage (postScript):
//   ExportFunctionMap.java --out=<path>
//
// @category m68k

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class ExportFunctionMap extends GhidraScript {

    private static class Row {
        String name;
        String entry;
        long bodySize;
        int insnCount;
        int callInsnCount;
        boolean external;
        boolean thunk;
    }

    private String outPath;

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());
        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_function_map.tsv";
        }

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        List<Row> rows = new ArrayList<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            Row r = new Row();
            r.name = f.getName();
            r.entry = f.getEntryPoint().toString();
            r.bodySize = f.getBody().getNumAddresses();
            r.external = f.isExternal();
            r.thunk = f.isThunk();

            int insn = 0;
            int callInsn = 0;
            InstructionIterator iit = listing.getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction in = iit.next();
                insn++;
                FlowType ft = in.getFlowType();
                if (ft != null && ft.isCall()) {
                    callInsn++;
                }
            }
            r.insnCount = insn;
            r.callInsnCount = callInsn;
            rows.add(r);
        }

        Collections.sort(rows, new Comparator<Row>() {
            @Override
            public int compare(Row a, Row b) {
                return a.entry.compareTo(b.entry);
            }
        });

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }
        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# ExportFunctionMap\n");
            w.write("generated_at_utc\t" + Instant.now().toString() + "\n");
            w.write("program_name\t" + currentProgram.getName() + "\n");
            w.write("language_id\t" + currentProgram.getLanguageID().getIdAsString() + "\n");
            w.write("image_base\t" + currentProgram.getImageBase().toString() + "\n");
            w.write("\n");
            w.write("entry\tname\tbody_size\tinsn_count\tcall_insn_count\texternal\tthunk\n");
            for (Row r : rows) {
                w.write(r.entry + "\t" + r.name + "\t" + r.bodySize + "\t" + r.insnCount + "\t"
                    + r.callInsnCount + "\t" + r.external + "\t" + r.thunk + "\n");
            }
        }

        println("Exported function map to: " + p.toAbsolutePath());
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
        }
    }
}
