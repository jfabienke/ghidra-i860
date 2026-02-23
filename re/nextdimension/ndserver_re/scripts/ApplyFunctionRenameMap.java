// Apply function renames from CSV.
//
// Usage (postScript):
//   ApplyFunctionRenameMap.java --map=<csv_path> [--out=<report_path>]
//
// CSV format:
//   address,new_name,confidence,evidence
//   0x7000210a,NDDriver_ProbeAndInitBoards,high,"..."
//
// @category m68k

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ApplyFunctionRenameMap extends GhidraScript {

    private static class RenameEntry {
        String rawAddress;
        String newName;
        String confidence;
        String evidence;
        int lineNo;
    }

    private String mapPath;
    private String outPath;

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());
        if (mapPath == null || mapPath.trim().isEmpty()) {
            printerr("missing --map=<csv_path>");
            return;
        }

        Path p = Paths.get(mapPath);
        if (!Files.exists(p)) {
            printerr("rename map not found: " + p.toAbsolutePath());
            return;
        }

        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_rename_apply_report.txt";
        }
        Path out = Paths.get(outPath);
        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }

        List<RenameEntry> entries = parseCsv(p);
        int applied = 0;
        int skipped = 0;
        int failed = 0;

        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            w.write("# Apply Function Rename Map\n\n");
            w.write("program: " + currentProgram.getName() + "\n");
            w.write("map: " + p.toAbsolutePath() + "\n");
            w.write("entries: " + entries.size() + "\n\n");

            for (RenameEntry e : entries) {
                if (monitor.isCancelled()) break;
                Address addr = parseAddressSafe(e.rawAddress);
                if (addr == null) {
                    failed++;
                    w.write("FAIL line " + e.lineNo + ": invalid address: " + e.rawAddress + "\n");
                    continue;
                }

                Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
                if (f == null) {
                    failed++;
                    w.write("FAIL line " + e.lineNo + ": no function at " + addr + " for " + e.newName + "\n");
                    continue;
                }

                String oldName = f.getName();
                if (oldName.equals(e.newName)) {
                    skipped++;
                    w.write("SKIP " + addr + ": already named " + e.newName + "\n");
                    continue;
                }

                try {
                    f.setName(e.newName, SourceType.USER_DEFINED);
                    applied++;
                    w.write("OK   " + addr + ": " + oldName + " -> " + e.newName);
                    if (e.confidence != null && !e.confidence.isEmpty()) {
                        w.write(" [" + e.confidence + "]");
                    }
                    if (e.evidence != null && !e.evidence.isEmpty()) {
                        w.write(" | " + e.evidence);
                    }
                    w.write("\n");
                }
                catch (Exception ex) {
                    failed++;
                    w.write("FAIL " + addr + ": " + oldName + " -> " + e.newName + " | " + ex.getMessage() + "\n");
                }
            }

            w.write("\nsummary: applied=" + applied + " skipped=" + skipped + " failed=" + failed + "\n");
        }

        println("Applied rename map: " + p.toAbsolutePath());
        println("Rename report: " + out.toAbsolutePath());
    }

    private List<RenameEntry> parseCsv(Path p) throws Exception {
        List<RenameEntry> out = new ArrayList<>();
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int lineNo = i + 1;
            if (line == null) continue;
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            if (lineNo == 1 && t.toLowerCase().startsWith("address,")) continue;

            List<String> cols = splitCsv(line);
            if (cols.size() < 2) continue;

            RenameEntry e = new RenameEntry();
            e.lineNo = lineNo;
            e.rawAddress = cols.get(0).trim();
            e.newName = cols.get(1).trim();
            e.confidence = (cols.size() > 2) ? cols.get(2).trim() : "";
            e.evidence = (cols.size() > 3) ? cols.get(3).trim() : "";
            if (e.rawAddress.isEmpty() || e.newName.isEmpty()) continue;
            out.add(e);
        }
        return out;
    }

    private List<String> splitCsv(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && (i + 1 < line.length()) && line.charAt(i + 1) == '"') {
                    cur.append('"');
                    i++;
                }
                else {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes) {
                out.add(cur.toString());
                cur.setLength(0);
            }
            else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }

    private Address parseAddressSafe(String raw) {
        if (raw == null) return null;
        String t = raw.trim().toLowerCase();
        if (t.isEmpty()) return null;
        if (t.startsWith("0x")) {
            t = t.substring(2);
        }
        try {
            return toAddr(Long.parseUnsignedLong(t, 16));
        }
        catch (Exception ex) {
            return null;
        }
    }

    private void parseArgs(String[] args) {
        if (args == null) return;
        for (String raw : args) {
            if (raw == null) continue;
            String a = raw.trim();
            if (a.startsWith("--map=")) {
                mapPath = a.substring("--map=".length()).trim();
            }
            else if (a.startsWith("--out=")) {
                outPath = a.substring("--out=".length()).trim();
            }
        }
    }
}
