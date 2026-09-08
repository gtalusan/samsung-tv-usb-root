// Find pointers to a target address anywhere in the program's data, then walk
// outward to identify the containing table entry. Used to locate the ext4
// match_table_t (struct match_token { int token; const char *pattern; }).
// Read-only. Args: 0xADDR of the string.
//
//@category Samsung.Ext4

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemoryBlock;

public class Ext4MatchTable extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length == 0) {
            println("usage: Ext4MatchTable.java 0xADDR");
            return;
        }
        long target = Long.parseLong(a[0].substring(2), 16);
        println("searching for 32-bit pointers to " + a[0]);

        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) {
                continue;
            }
            long start = b.getStart().getOffset();
            long size = b.getSize();
            byte[] buf = new byte[(int) Math.min(size, 8 * 1024 * 1024)];
            b.getBytes(b.getStart(), buf);
            for (int i = 0; i + 4 <= buf.length; i += 4) {
                long v = (buf[i] & 0xffL)
                       | ((buf[i + 1] & 0xffL) << 8)
                       | ((buf[i + 2] & 0xffL) << 16)
                       | ((buf[i + 3] & 0xffL) << 24);
                if (v != target) {
                    continue;
                }
                Address at = toAddr(start + i);
                println("  pointer at " + at + " in block " + b.getName());
                // In a match_table_t the token int precedes the pattern pointer.
                if (i >= 4) {
                    long tok = (buf[i - 4] & 0xffL)
                             | ((buf[i - 3] & 0xffL) << 8)
                             | ((buf[i - 2] & 0xffL) << 16)
                             | ((buf[i - 1] & 0xffL) << 24);
                    println("     preceding word (token?) = " + tok
                            + " (0x" + Long.toHexString(tok) + ")");
                }
                // Show neighbouring entries so the table shape is visible.
                for (int k = -2; k <= 2; k++) {
                    int o = i + k * 8;
                    if (o < 0 || o + 8 > buf.length) {
                        continue;
                    }
                    long t = (buf[o] & 0xffL) | ((buf[o + 1] & 0xffL) << 8)
                           | ((buf[o + 2] & 0xffL) << 16) | ((buf[o + 3] & 0xffL) << 24);
                    long p = (buf[o + 4] & 0xffL) | ((buf[o + 5] & 0xffL) << 8)
                           | ((buf[o + 6] & 0xffL) << 16) | ((buf[o + 7] & 0xffL) << 24);
                    println(String.format("     [%+d] token=%-6d pattern=0x%08x", k, t, p));
                }
            }
        }
        println("done");
    }
}
