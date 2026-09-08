// Annotate the szdrv_core NTFS parse path with VERIFIED facts.
// WRITES. Run with GHIDRA_WRITE=1.
// Every claim below was read out of the decompiler/disassembly of
// szdrv_core.ko sha256 3492781...bd5 (T-MSMDEUC-1500.9).
//@category Samsung.SZDRV
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class SzdrvAnnotate extends GhidraScript {
    private static final String CAT = "SZDRV";
    private static final String[][] NOTES = {
      {"0x1a6c4","parse_vbr",
       "VBR/boot-sector parse. CHECKED - well bounded.\n"
       +"Validates: sectors_per_cluster!=0, reserved==0, clusters_per_mft!=0,\n"
       +"clusters_per_idx!=0, sector_size is a power of 2 (my_log2 != -1),\n"
       +"cluster size in {0x200,0x800,0x2000,0x8000} (allowlist),\n"
       +"mft_record_size in {0x400,0x1000}, idx_record_size == 0x1000.\n"
       +"Derives vol fields used later as the trusted reference values:\n"
       +"  vol+0x68 mft_record_size      vol+0x70 = 0x30 (MFT usa_ofs)\n"
       +"  vol+0x74 = (mft_rec>>9)+1     vol+0x78 = usa_count*2+0x37 & ~7\n"
       +"  vol+0x84 idx_record_size      vol+0x8c = 0x28 (IDX usa_ofs)\n"
       +"  vol+0x90 = (idx>>9)+1"},

      {"0x106bc","pre_proc_fixup_array",
       "USA (update sequence array) APPLY, read path. Takes (vol, rec, usa_ofs, usa_count).\n"
       +"Itself performs NO bounds validation on usa_ofs/usa_count: it compares the\n"
       +"USN at rec+usa_ofs against rec+0x1fe and then writes usa_count-1 entries at\n"
       +"rec+0x3fe + n*0x200 (i.e. the last 2 bytes of each 512-byte sector).\n"
       +"SAFE ONLY BECAUSE all four callers validate first - see below. This is the\n"
       +"classic NTFS bug class and it is NOT present here; do not re-tread."},

      {"0x11a98","check_mft_entry_hdr",
       "MFT record header validator. STRICT - closes the USA bug class.\n"
       +"  usa_ofs (rec+4)   must be exactly 0x2A or 0x30\n"
       +"  usa_count (rec+6) must equal vol+0x74 = (mft_record_size>>9)+1\n"
       +"  attrs_offset (rec+0x14) must equal (usa_ofs + usa_count*2 + 7) & ~7\n"
       +"  bytes_allocated (rec+0x1c) must equal vol+0x68 (mft_record_size)\n"
       +"  bytes_in_use (rec+0x18) <= bytes_allocated\n"
       +"  if usa_ofs>0x2f, rec+0x2c (mft ref) must equal the requested entry number\n"
       +"Because bytes_allocated is forced == the allocation size, and usa_count is\n"
       +"forced == (size>>9)+1, the fixup writes land exactly inside the buffer."},

      {"0x214fc","get_mft_entry",
       "MFT read path. Buffer is SZDrv_malloc(vol+0x68) == mft_record_size exactly\n"
       +"(or a block-cache buffer via SZDrv_buf_getblk when the record fits one block).\n"
       +"Order: memcmp magic 'FILE' -> check_mft_entry_hdr -> pre_proc_fixup_array\n"
       +"with usa_ofs=*(u16*)(rec+4), usa_count=*(u16*)(rec+6).\n"
       +"VERIFIED: validation precedes the fixup. USA path closed."},

      {"0x12bb0","check_attrs",
       "Attribute header validator. PARTIAL - see the two gaps below.\n"
       +"Enforced for ALL attrs: attr_len >= 0x18, attr_len & 7 == 0,\n"
       +"  type in allowlist, non_resident <= 1, flags & 0x3ffe == 0,\n"
       +"  instance id < mrec+0x28.\n"
       +"GAP 1 (0x12bd4 bne 0x12c30): the test 'attr_len > vol->mft_record_size'\n"
       +"  at 0x12bdc is SKIPPED ENTIRELY when non_resident != 0. A non-resident\n"
       +"  attribute may declare any 8-aligned length >= 0x18 up to 0xFFFFFFF8.\n"
       +"GAP 2 (0x12d00 cmp r12,#0 / beq 0x12d68): the name_offset/name_length\n"
       +"  block at 0x12d68 (which enforces name_ofs==0x18 and derives the expected\n"
       +"  content offset) runs ONLY when non_resident == 0. For non-resident\n"
       +"  types 0x20,0x50,0x60,0x80,0xb0,0xc0,0xe0,0x100 the name fields are\n"
       +"  NEVER validated.\n"
       +"Types 0x10,0x30,0x40,0x70,0x90,0xd0 are forced resident (0x12d60 rejects\n"
       +"non_resident==1), so those are safe."},

      {"0x22a74","parse_mft_entry",
       "*** OFF-BY-ONE: attribute walk bound is applied AFTER use ***\n"
       +"Loop (0x22ad8..0x22b48):\n"
       +"  ofs = mrec[0x14] (attrs_offset)\n"
       +"  if (mrec[0x1c] < ofs) error            <- entry check, '<' not '<='\n"
       +"  type = *(u32*)(rec+ofs)                <- 0x22ae8 ldr r3,[r5,r4]\n"
       +"  while (type != -1) {\n"
       +"     check_attrs(rec+ofs); parse_attrs(rec+ofs);   <- USED HERE\n"
       +"     ofs += *(u32*)(rec+ofs+4);          <- 0x22b28 ldr r2,[r6,#4]\n"
       +"     if (mrec[0x1c] < ofs) error         <- 0x22b34 cmp r3,r4 / bcc  CHECKED HERE\n"
       +"     type = *(u32*)(rec+ofs);            <- 0x22b40, ofs may equal mrec[0x1c]\n"
       +"  }\n"
       +"Because the comparison is 'bytes_allocated < ofs' (strictly less), ofs ==\n"
       +"bytes_allocated PASSES. mrec[0x1c] is forced == the allocation size, so the\n"
       +"subsequent 4-byte type load at rec+bytes_allocated reads 4 bytes PAST the\n"
       +"end of the buffer. If those OOB bytes != 0xFFFFFFFF the loop body runs on\n"
       +"a wholly out-of-bounds attribute header.\n"
       +"Second walk at 0x22c60+ (attribute-list extension records) has the same shape."},

      {"0x1324c","proc_data_attr",
       "*** OOB READ: unvalidated name_length on non-resident DATA ***\n"
       +"Stack buffer at r11-0x22c, frame 'sub sp,sp,#0x224'. Copy loops:\n"
       +"  resident    (attr+0x12==0): src = attr+0x18\n"
       +"  non-resident(attr+0x12!=0): src = attr+0x40   <- 0x13414 add r2,r2,#0x40\n"
       +"  count = attr[9] (name_length, u8) halfwords   <- 0x132d0 ldrb r3,[r2,#9]\n"
       +"DESTINATION IS SAFE: max write = 255*2 + 2 = 512 bytes into 0x22c = 556\n"
       +"bytes of frame space. NOT a stack overflow - do not re-tread.\n"
       +"SOURCE IS NOT: for non-resident DATA (type 0x80) check_attrs never validated\n"
       +"name_length (GAP 2 above), so the read spans attr+0x40 .. attr+0x23E,\n"
       +"i.e. up to 574 bytes beyond the attribute header, which can sit at the very\n"
       +"end of the record buffer. Copies OOB heap/cache memory into a kernel struct."},

      {"0x15b90","proc_nres_attr",
       "Non-resident attribute / runlist decode.\n"
       +"0x15bf0: ldrh r3,[r4,#0x20]   -> mapping_pairs_offset, taken raw from disk\n"
       +"0x15bfc: ldrb r4,[r4,r3]      -> first mapping-pairs byte read at attr+that\n"
       +"NO bound is applied to mapping_pairs_offset before this index. Combined with\n"
       +"GAP 1 (non-resident attr_len unbounded) this is a second OOB read source.\n"
       +"Runlist decode then walks (len_bytes = b&0xf, ofs_bytes = b>>4) pairs."},

      {"0x10770","post_proc_fixup_array",
       "USA apply, WRITE path (put_dirty_*). CHECKED - validates usa_ofs itself:\n"
       +"rejects unless usa_ofs is 0x2a, 0x30, or vol+0x8c. Note the read path\n"
       +"(pre_proc_fixup_array) does NOT self-validate; it relies on its callers."},
    };

    @Override public void run() throws Exception {
        int n=0;
        for (String[] e : NOTES) {
            Address a = toAddr(Long.parseLong(e[0].substring(2),16));
            Function f = getFunctionContaining(a);
            if (f == null) { println("WARN no function at "+e[0]); continue; }
            f.setComment("["+e[1]+"]\n"+e[2]);
            createBookmark(f.getEntryPoint(), CAT, e[1]);
            println("annotated "+f.getName()+" @ "+f.getEntryPoint());
            n++;
        }
        println("plates written: "+n);
    }
}
