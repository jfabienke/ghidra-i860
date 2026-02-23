// Export references (read/write/call/data) to selected global addresses.
//
// Usage (postScript):
//   ExportGlobalRefMap.java --out=<path> --addr=0x7000c028,0x7000c06c,...
//
// @category m68k

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ExportGlobalRefMap extends GhidraScript {

    private String outPath;
    private List<Long> addresses = new ArrayList<>();

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());
        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_global_refmap.txt";
        }
        if (addresses.isEmpty()) {
            printerr("missing --addr=<hex,hex,...>");
            return;
        }

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        Listing listing = currentProgram.getListing();
        ReferenceManager refm = currentProgram.getReferenceManager();
        Memory mem = currentProgram.getMemory();

        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# Global Reference Map\n\n");
            w.write("generated_at_utc: " + Instant.now().toString() + "\n");
            w.write("program_name: " + currentProgram.getName() + "\n");
            w.write("language_id: " + currentProgram.getLanguageID().getIdAsString() + "\n\n");

            for (Long raw : addresses) {
                if (monitor.isCancelled()) break;
                Address a = toAddr(raw);
                w.write("===============================================================================\n");
                w.write("address: " + a + " (" + hex(raw) + ")\n");
                w.write("in_memory: " + mem.contains(a) + "\n");
                if (mem.contains(a)) {
                    long v = readU32Safe(mem, a);
                    w.write("u32_be: " + hex(v) + "\n");
                }
                w.write("\n");

                int total = 0;
                int readCount = 0;
                int writeCount = 0;
                int callCount = 0;
                int dataCount = 0;

                ReferenceIterator rit = refm.getReferencesTo(a);
                List<String> rows = new ArrayList<>();
                while (rit.hasNext()) {
                    Reference r = rit.next();
                    total++;
                    RefType rt = r.getReferenceType();
                    if (rt != null) {
                        if (rt.isRead()) readCount++;
                        if (rt.isWrite()) writeCount++;
                        if (rt.isCall()) callCount++;
                        if (rt.isData()) dataCount++;
                    }

                    Address from = r.getFromAddress();
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(from);
                    String fn = (f == null) ? "<no-func>" : f.getName() + " @ " + f.getEntryPoint();
                    Instruction insn = listing.getInstructionAt(from);
                    String insnText = (insn == null) ? "<no-insn>" : insn.toString();

                    rows.add(String.format("- from=%s fn=%s type=%s flags[r=%s w=%s c=%s d=%s] insn=%s",
                        from,
                        fn,
                        String.valueOf(rt),
                        (rt != null && rt.isRead()),
                        (rt != null && rt.isWrite()),
                        (rt != null && rt.isCall()),
                        (rt != null && rt.isData()),
                        sanitize(insnText)));
                }

                w.write(String.format("summary: refs=%d read=%d write=%d call=%d data=%d\n\n",
                    total, readCount, writeCount, callCount, dataCount));
                if (rows.isEmpty()) {
                    w.write("- (no references)\n\n");
                }
                else {
                    for (String s : rows) {
                        w.write(s + "\n");
                    }
                    w.write("\n");
                }
            }
        }

        println("Exported global ref map to: " + p.toAbsolutePath());
    }

    private long readU32Safe(Memory mem, Address a) {
        try {
            return mem.getInt(a) & 0xffffffffL;
        }
        catch (Exception ex) {
            return 0;
        }
    }

    private String hex(long v) {
        return String.format("0x%08x", v);
    }

    private String sanitize(String s) {
        if (s == null) return "";
        String t = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
        if (t.length() > 280) return t.substring(0, 277) + "...";
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
            else if (a.startsWith("--addr=")) {
                String body = a.substring("--addr=".length()).trim();
                for (String part : body.split(",")) {
                    Long v = parseU32(part.trim());
                    if (v != null) addresses.add(v);
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
