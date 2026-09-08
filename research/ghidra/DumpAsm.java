// Dump disassembly for an address range, with comments. Read-only.
//@category Samsung.CEC
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class DumpAsm extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Address lo = toAddr(Long.parseLong(a[0].substring(2), 16));
        Address hi = toAddr(Long.parseLong(a[1].substring(2), 16));
        Listing l = currentProgram.getListing();
        InstructionIterator it = l.getInstructions(lo, true);
        while (it.hasNext()) {
            Instruction i = it.next();
            if (i.getAddress().compareTo(hi) > 0) break;
            String c = l.getComment(CodeUnit.EOL_COMMENT, i.getAddress());
            println(i.getAddress() + "  " + i.toString() + (c == null ? "" : "   ; " + c));
        }
    }
}
