// Annotate the exFAT on-disk-metadata parsing path in exfat_core.ko.
//
// WRITES to the program. Run with GHIDRA_WRITE=1.
//
// Every claim below was read out of the decompiler/disassembly of
// exfat_core.ko from T-MSMDEUC-1500.9 (sha256 a96d482e...), version string
// "1.1.11p1(13-FEB-2013)". Negative results (bounded parsers) are recorded
// too so the next pass does not re-tread them.
//
//@category Samsung.Exfat

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ExfatAnnotate extends GhidraScript {

    private static final String CAT = "EXFAT-PARSER";

    // entry, label, plate comment
    private static final String[][] NOTES = {
        {"0x11be8", "exfat_get_uni_name_from_ext_entry",
         "*** LEAD-004 PRIMARY: unbounded stack write from directory metadata ***\n"
         + "void exfat_get_uni_name_from_ext_entry(sb, p_dir, entry, u16 *uniname)\n"
         + "  0x11c20  ldrb r5,[r0,#0x1]   <- num_ext, RAW BYTE from the on-disk\n"
         + "                                 file dentry. NOT clamped anywhere.\n"
         + "  0x11c48  cmp r3,#0x2 / bls   <- only guard: es->num_entries > 2\n"
         + "  0x11c70  mla r5,r3,r5,r4     <- end = uniname + 30*num_ext  (r3=0x1e)\n"
         + "  0x11c74  sub r5,r5,#0x1e\n"
         + "The loop copies 15 u16 (30 bytes) per name dentry until it reaches that\n"
         + "computed end pointer. num_ext is attacker-controlled 0..255, so the write\n"
         + "extent is up to 30*255 = 7650 bytes into the CALLER's buffer.\n"
         + "Callers pass a fixed-size STACK buffer (see ffsGetStat / ffsReadDir).\n"
         + "Loop also terminates early if an entry's type != 0x202 (TYPE_EXTEND),\n"
         + "so the attacker must supply that many genuine 0xC1 name dentries."},

        {"0x11794", "get_entry_set_in_dir",
         "Allocation side of LEAD-004 -- and why the 255 wrap is NOT exploitable.\n"
         + "  param_4 == 0 (ES_ALL_ENTRIES) => param_4 = *(byte*)(ep+1) + 1  (num_ext+1)\n"
         + "  param_4 = param_4 & 0xff                 <- truncation\n"
         + "  __kmalloc(param_4 * 0x20 + 0x10, GFP_KERNEL)\n"
         + "  piVar3[3] = param_4                      <- es->num_entries\n"
         + "num_ext=255 makes num_entries wrap to 0: allocation shrinks to 0x10 AND\n"
         + "the function returns early, skipping all entry-type validation. But the\n"
         + "consumer guard `2 < es->num_entries` then fails, so the copy loop never\n"
         + "runs. The wrap is a real truncation bug that happens to be dead here.\n"
         + "The DANGEROUS window is num_ext = 18..254: es->num_entries = num_ext+1\n"
         + "passes the >2 guard, and the copy walks to buf + 30*num_ext."},

        {"0x122e4", "ffsGetStat",
         "LEAD-004 sink #1. Stack buffer `short local_234[260]` = 520 bytes.\n"
         + "Calls fs_func+0x1c (get_uni_name_from_ext_entry) with &local_234.\n"
         + "Overflow when 30*num_ext > 520, i.e. num_ext >= 18.\n"
         + "num_ext=254 writes 7620 bytes into a 520-byte frame (~7.1 KB past).\n"
         + "Reached from VFS via exfat_getattr/exfat_iget (stat of a file)."},

        {"0x12694", "ffsReadDir",
         "LEAD-004 sink #2 -- BETTER REACHABILITY. Stack buffer\n"
         + "`short local_234[256]` = 512 bytes, and only `short local_34` sits\n"
         + "between it and the saved-register area.\n"
         + "Calls fs_func+0x1c with &local_234 for EVERY directory entry it lists.\n"
         + "Reached from exfat_iterate() -- i.e. a plain readdir()/ls of the\n"
         + "attacker's directory, no file needs to be opened."},

        {"0x14838", "__load_upcase_table",
         "CHECKED - NOT VULNERABLE (this is the CVE-2020-10720 / upcase bug class).\n"
         + "The `skip` path does index += uni with a u32 index, so index CAN exceed\n"
         + "0xFFFF, but both table indices are masked before use:\n"
         + "  col: uVar11 = (uVar12 & 0xffff) >> 8;   => 0..0xFF, table has 0x100 entries\n"
         + "  row: uVar11 = uVar12 & 0xff;            => 0..0xFF, row has 0x100 entries\n"
         + "Matches the fixed get_col_index(u16)/get_row_index(u16) shape in the\n"
         + "public 1.2.9 source. No OOB write here."},

        {"0x137cc", "exfat_mount",
         "VBR/BPB ingestion. NO validation of the boot-sector fields:\n"
         + "  *(iVar3+0x1c) = 1 << *(sbyte*)(param_2+0x6d)   <- sectors_per_clu_bits\n"
         + "                                                    raw, unvalidated shift\n"
         + "  uVar2 = bits + sector_size_bits; cluster_size = 1 << (uVar2 & 0xff)\n"
         + "  *(iVar3+0x44) = 1 << (uVar2 - 5 & 0xff)        <- dentries_per_clu\n"
         + "Only check is num_fats != 0 (offset 0x6e).\n"
         + "Shifts >= 32 are UNDEFINED on ARM (variable shift returns 0 rather than\n"
         + "trapping), so this yields nonsense geometry rather than a direct write.\n"
         + "Not a memory-corruption primitive on its own, but it poisons\n"
         + "cluster_size / dentries_per_clu used elsewhere -- worth revisiting as an\n"
         + "amplifier, NOT counted as a finding."},

        {"0x1465c", "load_alloc_bitmap",
         "Bitmap load. Allocation is derived from the on-disk size:\n"
         + "  n = ((size - 1) >> sector_size_bits) + 1;  __kmalloc(n*4, GFP_KERNEL)\n"
         + "then n sector_read() calls fill that array. Array size and loop bound are\n"
         + "the same variable, so no OOB in this function itself. Recorded as checked."},

        {"0x12b60", "extract_uni_name_from_name_entry",
         "CHECKED - bounded in isolation. Copies at most 15 u16 (i < 30, i += 2)\n"
         + "from one name dentry and NUL-terminates. The defect is in the CALLER\n"
         + "(exfat_get_uni_name_from_ext_entry), which advances the destination\n"
         + "15 u16 at a time for an unbounded number of iterations."},
    };

    private static final Set<String> SINKS = new HashSet<>(Arrays.asList(
        "memcpy", "memmove", "__memcpy", "__memzero", "memset", "strncpy",
        "__kmalloc", "kmalloc", "kmem_cache_alloc", "kfree", "sector_read",
        "buf_getblk", "get_entry_in_dir", "get_entry_set_in_dir"));

    @Override
    public void run() throws Exception {
        int plates = 0, marks = 0, calls = 0;
        for (String[] n : NOTES) {
            Address a = addr(n[0]);
            Function f = getFunctionContaining(a);
            if (f == null) {
                println("WARN no function at " + n[0] + " (" + n[1] + ")");
                continue;
            }
            f.setComment("[" + n[1] + "]\n" + n[2]);
            plates++;
            createBookmark(f.getEntryPoint(), CAT, n[1]);
            marks++;
            calls += tagSinkCalls(f);
            println("annotated " + f.getName() + " @ " + f.getEntryPoint()
                    + "  body=" + f.getBody().getNumAddresses());
        }
        println("");
        println("plate comments: " + plates + "  bookmarks: " + marks
                + "  sink call sites tagged: " + calls);
    }

    private int tagSinkCalls(Function f) {
        int n = 0;
        InstructionIterator it =
            currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) {
                continue;
            }
            for (Reference r : ins.getReferencesFrom()) {
                Symbol s = currentProgram.getSymbolTable()
                        .getPrimarySymbol(r.getToAddress());
                if (s == null) {
                    continue;
                }
                String base = s.getName();
                int at = base.indexOf('@');
                if (at > 0) {
                    base = base.substring(0, at);
                }
                if (!SINKS.contains(base)) {
                    continue;
                }
                setEOLComment(ins.getAddress(), "SINK: " + base);
                createBookmark(ins.getAddress(), CAT,
                        "sink " + base + " in " + f.getName());
                n++;
            }
        }
        return n;
    }

    private Address addr(String hex) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseLong(hex.substring(2), 16));
    }
}
