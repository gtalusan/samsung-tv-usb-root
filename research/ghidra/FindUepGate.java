// Locate the UEP verification gate in the shipped kernel image.
// Anchors on the retained __func__ strings (no kallsyms in this image).
//@category Samsung.UEP
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.mem.MemoryBlock;

public class FindUepGate extends GhidraScript {
    private static final String[] NEEDLES = {
        "SfdUepHandleVerificationResult", "SfdUepVerifyFileSignature",
        "SfdUepCheckFileSignature", "is not signed", "SfdOpenUepContext"
    };

    @Override
    public void run() throws Exception {
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        Address start = blocks[0].getStart();
        for (String needle : NEEDLES) {
            println("=== \"" + needle + "\"");
            Address a = start;
            int hits = 0;
            while (a != null && hits < 4) {
                a = find(a, needle.getBytes());
                if (a == null) break;
                println("  string @ " + a);
                Reference[] refs = getReferencesTo(a);
                if (refs.length == 0) {
                    println("    (no direct refs -- likely reached via a literal pool)");
                } else {
                    for (Reference r : refs) {
                        Function f = getFunctionContaining(r.getFromAddress());
                        println("    <- " + r.getFromAddress() + "  in "
                                + (f == null ? "<no function>" : f.getName() + "@" + f.getEntryPoint()));
                    }
                }
                // literal-pool scan: find any 4-byte word in the image equal to this address
                long target = a.getOffset();
                byte[] le = new byte[] {
                    (byte)(target & 0xff), (byte)((target >> 8) & 0xff),
                    (byte)((target >> 16) & 0xff), (byte)((target >> 24) & 0xff) };
                Address p = start; int pools = 0;
                while (pools < 6) {
                    p = find(p, le);
                    if (p == null) break;
                    Function f = getFunctionContaining(p);
                    println("    pool word @ " + p + (f == null ? "" : "  in " + f.getName()));
                    p = p.add(1); pools++;
                }
                a = a.add(1); hits++;
            }
        }
    }
}
