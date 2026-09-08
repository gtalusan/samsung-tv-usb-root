// Report code coverage/boundaries across an address range.
//@category Samsung.CEC
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class CheckExtent extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long lo = Long.parseLong(a[0].substring(2), 16);
        long hi = Long.parseLong(a[1].substring(2), 16);
        Listing l = currentProgram.getListing();
        long undef = 0, insn = 0;
        for (long x = lo; x < hi; x++) {
            Address ad = toAddr(x);
            CodeUnit cu = l.getCodeUnitContaining(ad);
            if (cu instanceof Instruction) insn++; else undef++;
        }
        println("range " + a[0] + ".." + a[1] + "  instruction bytes=" + insn + "  non-instruction bytes=" + undef);
        for (Function f : currentProgram.getFunctionManager().getFunctions(toAddr(lo), true)) {
            if (f.getEntryPoint().getOffset() >= hi) break;
            println("  FUNC " + f.getName() + " @ " + f.getEntryPoint()
                + "  body=" + f.getBody().getNumAddresses()
                + "  max=" + f.getBody().getMaxAddress());
        }
    }
}
