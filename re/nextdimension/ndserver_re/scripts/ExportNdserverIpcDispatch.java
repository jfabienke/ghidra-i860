// Export IPC dispatch evidence centered on a dispatcher function.
//
// Usage (postScript):
//   ExportNdserverIpcDispatch.java --out=<path> [--func=0x700031b4] [--table=0x7000c028] [--limit=64]
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportNdserverIpcDispatch extends GhidraScript {

    private static class SlotInfo {
        int slot;
        Address slotPtrAddr;
        Address descAddr;
        Address handlerPtrAddr;
        Address handlerAddr;
        Function handlerFunc;
    }

    private String outPath;
    private long funcAddr = 0x700031b4L;
    private long tableAddr = 0x7000c028L;
    private int tableLimit = 64;
    private int decompTimeoutSec = 60;

    @Override
    public void run() throws Exception {
        parseArgs(getScriptArgs());
        if (outPath == null || outPath.trim().isEmpty()) {
            outPath = "/tmp/" + currentProgram.getName() + "_ipc_dispatch.txt";
        }

        Path p = Paths.get(outPath);
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refm = currentProgram.getReferenceManager();

        Address dispatcherAddr = toAddr(funcAddr);
        Function dispatcher = fm.getFunctionAt(dispatcherAddr);

        try (BufferedWriter w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
            w.write("# NDserver IPC Dispatch Report\n\n");
            w.write("generated_at_utc: " + Instant.now().toString() + "\n");
            w.write("program_name: " + currentProgram.getName() + "\n");
            w.write("language_id: " + currentProgram.getLanguageID().getIdAsString() + "\n");
            w.write("dispatcher_addr: " + hex(funcAddr) + "\n");
            w.write("dispatch_table_addr: " + hex(tableAddr) + "\n\n");

            if (dispatcher == null) {
                w.write("dispatcher_function: (not found)\n");
                return;
            }

            w.write("dispatcher_function: " + dispatcher.getName() + " @ " + dispatcher.getEntryPoint() + "\n\n");

            Set<String> codeCallers = new LinkedHashSet<>();
            Set<String> dataRefs = new LinkedHashSet<>();

            ReferenceIterator toDisp = refm.getReferencesTo(dispatcher.getEntryPoint());
            while (toDisp.hasNext()) {
                Reference r = toDisp.next();
                RefType rt = r.getReferenceType();
                Function rf = fm.getFunctionContaining(r.getFromAddress());
                String from = r.getFromAddress().toString();
                String where = (rf == null)
                    ? "<no-func> @ " + from
                    : rf.getName() + " @ " + rf.getEntryPoint() + " -> " + from;
                if (rt != null && rt.isCall()) {
                    codeCallers.add(where);
                }
                else {
                    dataRefs.add(where + " [" + rt + "]");
                }
            }

            w.write("## Direct Callers\n\n");
            if (codeCallers.isEmpty()) {
                w.write("- (none)\n");
            }
            else {
                for (String s : codeCallers) {
                    w.write("- " + s + "\n");
                }
            }
            w.write("\n");

            w.write("## Non-Call References To Dispatcher\n\n");
            if (dataRefs.isEmpty()) {
                w.write("- (none)\n");
            }
            else {
                for (String s : dataRefs) {
                    w.write("- " + s + "\n");
                }
            }
            w.write("\n");

            w.write("## Dispatcher Outgoing Calls\n\n");
            InstructionIterator iit = listing.getInstructions(dispatcher.getBody(), true);
            int outCalls = 0;
            while (iit.hasNext()) {
                Instruction insn = iit.next();
                if (insn.getFlowType() == null || !insn.getFlowType().isCall()) continue;
                outCalls++;
                Address[] flows = insn.getFlows();
                if (flows == null || flows.length == 0) {
                    w.write("- " + insn.getAddress() + " -> <indirect>\n");
                    continue;
                }
                for (Address to : flows) {
                    Function callee = fm.getFunctionAt(to);
                    if (callee == null) callee = fm.getFunctionContaining(to);
                    if (callee != null) {
                        w.write("- " + insn.getAddress() + " -> " + callee.getName() + " @ " + callee.getEntryPoint() + "\n");
                    }
                    else {
                        w.write("- " + insn.getAddress() + " -> " + to + "\n");
                    }
                }
            }
            if (outCalls == 0) {
                w.write("- (none)\n");
            }
            w.write("\n");

            w.write("## Dispatch Table Slots (index -> descriptor -> handler)\n\n");
            Address tableBase = toAddr(tableAddr);
            int validSlots = 0;
            List<SlotInfo> slots = new ArrayList<>();
            for (int i = 0; i < tableLimit; i++) {
                Address slotPtrAddr = tableBase.add((long) i * 4L);
                if (!mem.contains(slotPtrAddr)) break;
                long descRaw = readU32(mem, slotPtrAddr);
                if (descRaw == 0) continue;
                Address descAddr = toAddr(descRaw);
                if (!mem.contains(descAddr)) continue;

                Address handlerPtrAddr = descAddr.add(0x3c);
                if (!mem.contains(handlerPtrAddr)) continue;
                long handlerRaw = readU32(mem, handlerPtrAddr);
                if (handlerRaw == 0) continue;
                Address handlerAddr = toAddr(handlerRaw);
                if (!mem.contains(handlerAddr)) continue;

                Function handler = fm.getFunctionAt(handlerAddr);
                if (handler == null) handler = fm.getFunctionContaining(handlerAddr);

                String handlerName = (handler == null)
                    ? "<no-func>"
                    : handler.getName() + " @ " + handler.getEntryPoint();

                validSlots++;
                w.write(String.format("- slot=%d slot_ptr=%s desc=%s handler_ptr=%s handler=%s\n",
                    i,
                    slotPtrAddr.toString(),
                    descAddr.toString(),
                    handlerPtrAddr.toString(),
                    handlerName));

                SlotInfo si = new SlotInfo();
                si.slot = i;
                si.slotPtrAddr = slotPtrAddr;
                si.descAddr = descAddr;
                si.handlerPtrAddr = handlerPtrAddr;
                si.handlerAddr = handlerAddr;
                si.handlerFunc = handler;
                slots.add(si);
            }
            if (validSlots == 0) {
                w.write("- (none decoded)\n");
            }
            w.write("\n");

            w.write("## References To Dispatch Table Base\n\n");
            Set<String> tableRefs = new LinkedHashSet<>();
            ReferenceIterator rtab = refm.getReferencesTo(tableBase);
            while (rtab.hasNext()) {
                Reference r = rtab.next();
                Function rf = fm.getFunctionContaining(r.getFromAddress());
                String from = r.getFromAddress().toString();
                if (rf == null) {
                    tableRefs.add("<no-func> @ " + from + " [" + r.getReferenceType() + "]");
                }
                else {
                    tableRefs.add(rf.getName() + " @ " + rf.getEntryPoint() + " -> " + from +
                        " [" + r.getReferenceType() + "]");
                }
            }
            if (tableRefs.isEmpty()) {
                w.write("- (none)\n");
            }
            else {
                for (String s : tableRefs) {
                    w.write("- " + s + "\n");
                }
            }
            w.write("\n");

            w.write("## Slot Handler Details\n\n");
            if (slots.isEmpty()) {
                w.write("- (none)\n\n");
            }
            else {
                DecompInterface slotDecomp = new DecompInterface();
                slotDecomp.openProgram(currentProgram);
                try {
                    for (SlotInfo si : slots) {
                        if (monitor.isCancelled()) break;
                        w.write(String.format("### slot %d\n\n", si.slot));
                        w.write("- descriptor: " + si.descAddr + "\n");
                        w.write("- handler_address: " + si.handlerAddr + "\n");
                        if (si.handlerFunc == null) {
                            w.write("- handler_function: <no-func>\n\n");
                            continue;
                        }

                        w.write("- handler_function: " + si.handlerFunc.getName() + " @ " +
                            si.handlerFunc.getEntryPoint() + "\n");

                        Set<String> hCallers = new LinkedHashSet<>();
                        ReferenceIterator hr = refm.getReferencesTo(si.handlerFunc.getEntryPoint());
                        while (hr.hasNext()) {
                            Reference r = hr.next();
                            if (!r.getReferenceType().isCall()) continue;
                            Function cf = fm.getFunctionContaining(r.getFromAddress());
                            if (cf == null) {
                                hCallers.add("<no-func> @ " + r.getFromAddress());
                            }
                            else {
                                hCallers.add(cf.getName() + " @ " + cf.getEntryPoint() +
                                    " -> " + r.getFromAddress());
                            }
                        }
                        if (hCallers.isEmpty()) {
                            w.write("- direct_callers: (none)\n");
                        }
                        else {
                            w.write("- direct_callers:\n");
                            for (String cs : hCallers) {
                                w.write("  - " + cs + "\n");
                            }
                        }

                        DecompileResults hdr = slotDecomp.decompileFunction(si.handlerFunc, decompTimeoutSec, monitor);
                        if (hdr == null || !hdr.decompileCompleted() || hdr.getDecompiledFunction() == null) {
                            String err = (hdr == null) ? "null results" : hdr.getErrorMessage();
                            w.write("- decompilation: failed (" + sanitize(err) + ")\n\n");
                        }
                        else {
                            w.write("- decompilation:\n\n");
                            w.write("```c\n");
                            w.write(hdr.getDecompiledFunction().getC());
                            w.write("\n```\n\n");
                        }
                    }
                }
                finally {
                    slotDecomp.dispose();
                }
            }

            w.write("## Dispatcher Decompiled C\n\n");
            DecompInterface di = new DecompInterface();
            di.openProgram(currentProgram);
            try {
                DecompileResults dr = di.decompileFunction(dispatcher, decompTimeoutSec, monitor);
                if (dr == null || !dr.decompileCompleted() || dr.getDecompiledFunction() == null) {
                    String err = (dr == null) ? "null results" : dr.getErrorMessage();
                    w.write("[decompilation failed] " + sanitize(err) + "\n");
                }
                else {
                    w.write("```c\n");
                    w.write(dr.getDecompiledFunction().getC());
                    w.write("\n```\n");
                }
            }
            finally {
                di.dispose();
            }
        }

        println("Exported ND IPC dispatch report to: " + p.toAbsolutePath());
    }

    private long readU32(Memory mem, Address a) throws Exception {
        int v = mem.getInt(a);
        return v & 0xffffffffL;
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
            else if (a.startsWith("--func=")) {
                Long v = parseU32(a.substring("--func=".length()).trim());
                if (v != null) funcAddr = v;
            }
            else if (a.startsWith("--table=")) {
                Long v = parseU32(a.substring("--table=".length()).trim());
                if (v != null) tableAddr = v;
            }
            else if (a.startsWith("--limit=")) {
                try {
                    int n = Integer.parseInt(a.substring("--limit=".length()).trim());
                    if (n > 0) tableLimit = n;
                }
                catch (NumberFormatException ignored) {}
            }
        }
    }

    private Long parseU32(String raw) {
        if (raw == null) return null;
        String t = raw.trim().toLowerCase();
        if (t.startsWith("0x")) t = t.substring(2);
        try {
            return Long.parseUnsignedLong(t, 16);
        }
        catch (Exception ex) {
            return null;
        }
    }
}
