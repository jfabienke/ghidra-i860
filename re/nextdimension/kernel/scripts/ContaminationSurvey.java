// Survey contamination in the ND i860 kernel binary.
// Classifies 1KB blocks by content type using byte-level heuristics
// and compares against decoded i860 instructions from the analysis pipeline.
//
// Run as postScript after I860Import.java.
//
// @category i860

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class ContaminationSurvey extends GhidraScript {

    private static final int BLK = 1024;

    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        StringBuilder sb = new StringBuilder();
        sb.append("=== i860 Kernel Contamination Survey ===\n\n");

        for (MemoryBlock mblock : memory.getBlocks()) {
            if (!mblock.isExecute() || !mblock.isInitialized()) continue;

            long start = mblock.getStart().getOffset();
            long end = mblock.getEnd().getOffset();
            long size = end - start + 1;
            if (size > Integer.MAX_VALUE) continue;

            sb.append(String.format("Block: %s  %08X-%08X  %,d bytes\n\n",
                mblock.getName(), start, end, size));

            byte[] bytes = new byte[(int) size];
            mblock.getBytes(mblock.getStart(), bytes);

            List<long[]> blockStats = new ArrayList<>();   // addr, type ordinal
            List<String> blockTypes = new ArrayList<>();
            List<int[]> blockDetail = new ArrayList<>();    // i860, printable%, null%, m68k, x86, entropy*10

            for (int off = 0; off < bytes.length; off += BLK) {
                if (monitor.isCancelled()) break;
                int len = Math.min(BLK, bytes.length - off);
                long addr = start + off;

                // Count decoded i860 instructions
                int i860 = 0;
                for (int j = 0; j + 3 < len; j += 4) {
                    Address a = space.getAddress(addr + j);
                    if (listing.getInstructionAt(a) != null) i860++;
                }

                // Byte statistics
                int printable = 0, nulls = 0;
                int[] freq = new int[256];
                for (int j = 0; j < len; j++) {
                    int b = bytes[off + j] & 0xFF;
                    freq[b]++;
                    if (b == 0) nulls++;
                    if ((b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09)
                        printable++;
                }

                // Shannon entropy
                double ent = 0;
                for (int f : freq) {
                    if (f > 0) {
                        double p = (double) f / len;
                        ent -= p * (Math.log(p) / Math.log(2));
                    }
                }

                // m68k signatures (big-endian 16-bit scan)
                int m68k = 0;
                for (int j = 0; j + 1 < len; j += 2) {
                    int w = ((bytes[off + j] & 0xFF) << 8) | (bytes[off + j + 1] & 0xFF);
                    if (w == 0x4E75) m68k += 3;          // RTS
                    else if (w == 0x4E56) m68k += 3;     // LINK
                    else if (w == 0x4E5E) m68k += 3;     // UNLK
                    else if (w == 0x4E71) m68k += 2;     // NOP
                    else if ((w & 0xFFF0) == 0x4EA0) m68k += 2; // JSR (An)
                    else if (w == 0x4EB9) m68k += 2;     // JSR abs.l
                    else if ((w & 0xFF00) == 0x4800) m68k++;  // MOVEM save
                    else if ((w & 0xFF00) == 0x4C00) m68k++;  // MOVEM restore
                    else if ((w & 0xFF00) == 0x2F00) m68k++;  // MOVE.L Dn,-(SP)
                }

                // x86 signatures (byte-level scan)
                int x86 = 0;
                for (int j = 0; j + 1 < len; j++) {
                    int b0 = bytes[off + j] & 0xFF;
                    int b1 = bytes[off + j + 1] & 0xFF;
                    if (b0 == 0x55 && b1 == 0x89) x86 += 3;      // push ebp; mov ebp,...
                    else if (b0 == 0x55 && b1 == 0x8B) x86 += 3;  // push ebp; mov ...
                    else if (b0 == 0x5D && b1 == 0xC3) x86 += 3;  // pop ebp; ret
                    else if (b0 == 0xC3) x86 += 2;                // ret
                    else if (b0 == 0xC2) x86++;                   // ret imm16
                    else if (b0 == 0xE8) x86 += 2;                // call near
                    else if (b0 == 0xE9) x86++;                   // jmp near
                    else if (b0 == 0x83 && b1 == 0xEC) x86 += 2;  // sub esp, imm8
                    else if (b0 == 0x83 && b1 == 0xC4) x86 += 2;  // add esp, imm8
                    else if (b0 == 0xFF && (b1 & 0x38) == 0x10) x86++; // call [reg+disp]
                }

                // Mach-O magic check
                boolean macho = false;
                int machoCpu = 0;
                for (int j = 0; j + 3 < len; j += 4) {
                    int w32 = ((bytes[off + j] & 0xFF) << 24) | ((bytes[off + j + 1] & 0xFF) << 16)
                            | ((bytes[off + j + 2] & 0xFF) << 8) | (bytes[off + j + 3] & 0xFF);
                    if (w32 == 0xFEEDFACE || w32 == 0xCEFAEDFE) {
                        macho = true;
                        boolean be = (w32 == 0xFEEDFACE);
                        if (j + 7 < len) {
                            if (be) {
                                machoCpu = ((bytes[off + j + 4] & 0xFF) << 24) | ((bytes[off + j + 5] & 0xFF) << 16)
                                         | ((bytes[off + j + 6] & 0xFF) << 8) | (bytes[off + j + 7] & 0xFF);
                            } else {
                                machoCpu = (bytes[off + j + 4] & 0xFF) | ((bytes[off + j + 5] & 0xFF) << 8)
                                         | ((bytes[off + j + 6] & 0xFF) << 16) | ((bytes[off + j + 7] & 0xFF) << 24);
                            }
                        }
                    }
                }

                // Classify
                int pctPrint = printable * 100 / len;
                int pctNull = nulls * 100 / len;
                int maxI860 = len / 4;
                int pctI860 = (maxI860 > 0) ? i860 * 100 / maxI860 : 0;

                String type;
                if (pctNull > 80) {
                    type = "NULL_PAD";
                } else if (macho) {
                    if (machoCpu == 6 || machoCpu == 7) type = "MACHO_X86";       // CPU_TYPE_I386/X86
                    else if (machoCpu == 18) type = "MACHO_PPC";                  // CPU_TYPE_POWERPC
                    else if (machoCpu == 6 || (machoCpu & 0xFF) == 6) type = "MACHO_M68K"; // CPU_TYPE_MC680x0
                    else if (machoCpu == 15) type = "MACHO_I860";                 // CPU_TYPE_I860
                    else type = "MACHO_UNK(" + machoCpu + ")";
                } else if (pctPrint > 55) {
                    type = "ASCII_TEXT";
                } else if (pctI860 > 25) {
                    type = "I860_CODE";
                } else if (m68k >= 10 && m68k > x86 * 2) {
                    type = "M68K_CODE";
                } else if (x86 >= 10 && x86 > m68k * 2) {
                    type = "X86_CODE";
                } else if (pctI860 > 0) {
                    type = "I860_SPARSE";
                } else if (m68k > 3 && m68k > x86) {
                    type = "M68K_DATA";
                } else if (x86 > 3 && x86 > m68k) {
                    type = "X86_DATA";
                } else {
                    type = "BIN_DATA";
                }

                blockTypes.add(type);
                blockDetail.add(new int[]{ i860, pctPrint, pctNull, m68k, x86, (int)(ent * 10) });
            }

            // Merge adjacent same-type blocks into regions
            List<String[]> regions = new ArrayList<>();
            if (!blockTypes.isEmpty()) {
                String curType = blockTypes.get(0);
                long regStart = start;
                int regI860 = blockDetail.get(0)[0];

                for (int i = 1; i < blockTypes.size(); i++) {
                    String t = blockTypes.get(i);
                    if (!t.equals(curType)) {
                        long regEnd = start + (long) i * BLK - 1;
                        regions.add(new String[]{
                            String.format("%08X", regStart),
                            String.format("%08X", Math.min(regEnd, end)),
                            String.format("%d", Math.min(regEnd, end) - regStart + 1),
                            curType,
                            String.valueOf(regI860)
                        });
                        curType = t;
                        regStart = start + (long) i * BLK;
                        regI860 = blockDetail.get(i)[0];
                    } else {
                        regI860 += blockDetail.get(i)[0];
                    }
                }
                // Final region
                regions.add(new String[]{
                    String.format("%08X", regStart),
                    String.format("%08X", end),
                    String.format("%d", end - regStart + 1),
                    curType,
                    String.valueOf(regI860)
                });
            }

            // Print region table
            sb.append(String.format("%-10s  %-10s  %10s  %-14s  %s\n",
                "Start", "End", "Size", "Type", "i860 Insns"));
            sb.append(String.format("%-10s  %-10s  %10s  %-14s  %s\n",
                "----------", "----------", "----------", "--------------", "----------"));

            Map<String, Long> typeSizes = new LinkedHashMap<>();
            Map<String, Integer> typeInsns = new LinkedHashMap<>();

            for (String[] r : regions) {
                long sz = Long.parseLong(r[2]);
                sb.append(String.format("%-10s  %-10s  %,10d  %-14s  %s\n",
                    r[0], r[1], sz, r[3], r[4]));
                typeSizes.merge(r[3], sz, Long::sum);
                typeInsns.merge(r[3], Integer.parseInt(r[4]), Integer::sum);
            }

            // Type summary
            sb.append(String.format("\n--- Type Summary for %s ---\n", mblock.getName()));
            long total = 0;
            for (long v : typeSizes.values()) total += v;

            sb.append(String.format("%-14s  %10s  %6s  %s\n", "Type", "Bytes", "%", "i860 Insns"));
            sb.append(String.format("%-14s  %10s  %6s  %s\n", "--------------", "----------", "------", "----------"));

            // Sort by size descending
            List<Map.Entry<String, Long>> sorted = new ArrayList<>(typeSizes.entrySet());
            sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            for (Map.Entry<String, Long> e : sorted) {
                sb.append(String.format("%-14s  %,10d  %5.1f%%  %d\n",
                    e.getKey(), e.getValue(),
                    e.getValue() * 100.0 / total,
                    typeInsns.getOrDefault(e.getKey(), 0)));
            }
            sb.append(String.format("%-14s  %,10d  %5.1f%%  %d\n",
                "TOTAL", total, 100.0,
                typeInsns.values().stream().mapToInt(Integer::intValue).sum()));
            sb.append("\n");
        }

        // Per-block detail (1KB granularity)
        sb.append("\n=== Per-Block Detail (1KB) ===\n");
        sb.append(String.format("%-10s  %-14s  %4s  %4s  %4s  %4s  %4s  %3s\n",
            "Address", "Type", "i860", "asc%", "nul%", "m68k", "x86", "ent"));
        sb.append(String.format("%-10s  %-14s  %4s  %4s  %4s  %4s  %4s  %3s\n",
            "----------", "--------------", "----", "----", "----", "----", "----", "---"));

        for (MemoryBlock mblock : memory.getBlocks()) {
            if (!mblock.isExecute() || !mblock.isInitialized()) continue;

            long bstart = mblock.getStart().getOffset();
            long bend = mblock.getEnd().getOffset();
            long bsize = bend - bstart + 1;
            if (bsize > Integer.MAX_VALUE) continue;

            byte[] bytes = new byte[(int) bsize];
            mblock.getBytes(mblock.getStart(), bytes);

            int idx = 0;
            for (int off = 0; off < bytes.length; off += BLK) {
                if (monitor.isCancelled()) break;
                int len = Math.min(BLK, bytes.length - off);
                long addr = bstart + off;

                // Recompute stats for detail output (we don't have them stored per block for this block)
                int i860 = 0;
                for (int j = 0; j + 3 < len; j += 4) {
                    Address a = space.getAddress(addr + j);
                    if (listing.getInstructionAt(a) != null) i860++;
                }
                int printable = 0, nulls = 0;
                for (int j = 0; j < len; j++) {
                    int b = bytes[off + j] & 0xFF;
                    if (b == 0) nulls++;
                    if ((b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09)
                        printable++;
                }
                int m68k = 0;
                for (int j = 0; j + 1 < len; j += 2) {
                    int w = ((bytes[off + j] & 0xFF) << 8) | (bytes[off + j + 1] & 0xFF);
                    if (w == 0x4E75) m68k += 3;
                    else if (w == 0x4E56) m68k += 3;
                    else if (w == 0x4E5E) m68k += 3;
                    else if (w == 0x4E71) m68k += 2;
                    else if ((w & 0xFFF0) == 0x4EA0) m68k += 2;
                    else if (w == 0x4EB9) m68k += 2;
                    else if ((w & 0xFF00) == 0x4800) m68k++;
                    else if ((w & 0xFF00) == 0x4C00) m68k++;
                    else if ((w & 0xFF00) == 0x2F00) m68k++;
                }
                int x86 = 0;
                for (int j = 0; j + 1 < len; j++) {
                    int b0 = bytes[off + j] & 0xFF;
                    int b1 = bytes[off + j + 1] & 0xFF;
                    if (b0 == 0x55 && b1 == 0x89) x86 += 3;
                    else if (b0 == 0x55 && b1 == 0x8B) x86 += 3;
                    else if (b0 == 0x5D && b1 == 0xC3) x86 += 3;
                    else if (b0 == 0xC3) x86 += 2;
                    else if (b0 == 0xC2) x86++;
                    else if (b0 == 0xE8) x86 += 2;
                    else if (b0 == 0xE9) x86++;
                    else if (b0 == 0x83 && b1 == 0xEC) x86 += 2;
                    else if (b0 == 0x83 && b1 == 0xC4) x86 += 2;
                    else if (b0 == 0xFF && (b1 & 0x38) == 0x10) x86++;
                }
                int[] freq = new int[256];
                for (int j = 0; j < len; j++) freq[bytes[off + j] & 0xFF]++;
                double ent = 0;
                for (int f : freq) {
                    if (f > 0) { double p = (double) f / len; ent -= p * (Math.log(p) / Math.log(2)); }
                }

                // Reuse classification logic
                int pctP = printable * 100 / len;
                int pctN = nulls * 100 / len;
                int maxI = len / 4;
                int pctI = (maxI > 0) ? i860 * 100 / maxI : 0;

                boolean macho = false;
                for (int j = 0; j + 3 < len; j += 4) {
                    int w32 = ((bytes[off+j]&0xFF)<<24)|((bytes[off+j+1]&0xFF)<<16)
                             |((bytes[off+j+2]&0xFF)<<8)|(bytes[off+j+3]&0xFF);
                    if (w32 == 0xFEEDFACE || w32 == 0xCEFAEDFE) macho = true;
                }

                String type;
                if (pctN > 80) type = "NULL_PAD";
                else if (macho) type = "MACHO_*";
                else if (pctP > 55) type = "ASCII_TEXT";
                else if (pctI > 25) type = "I860_CODE";
                else if (m68k >= 10 && m68k > x86 * 2) type = "M68K_CODE";
                else if (x86 >= 10 && x86 > m68k * 2) type = "X86_CODE";
                else if (pctI > 0) type = "I860_SPARSE";
                else if (m68k > 3 && m68k > x86) type = "M68K_DATA";
                else if (x86 > 3 && x86 > m68k) type = "X86_DATA";
                else type = "BIN_DATA";

                sb.append(String.format("%08X    %-14s  %4d  %3d%%  %3d%%  %4d  %4d  %3.1f\n",
                    addr, type, i860, pctP, pctN, m68k, x86, ent));

                idx++;
            }
        }

        String output = sb.toString();
        printf("%s", output);

        String outPath = "/tmp/i860_contamination_survey.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        pw.print(output);
        pw.close();
        printf("\nWritten to: %s\n", outPath);
    }
}
