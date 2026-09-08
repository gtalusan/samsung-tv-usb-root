// Find calls to mount() and report the flags argument (4th arg = r3 on ARM EABI).
//@category Samsung.Storage
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FindMountCalls extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolIterator syms = currentProgram.getSymbolTable().getAllSymbols(true);
        while (syms.hasNext()) {
            Symbol s = syms.next();
            String n = s.getName();
            int at = n.indexOf('@'); if (at > 0) n = n.substring(0, at);
            if (!n.equals("mount")) continue;
            for (Reference r : getReferencesTo(s.getAddress())) {
                Function f = getFunctionContaining(r.getFromAddress());
                println("=== call to mount() at " + r.getFromAddress()
                        + " in " + (f == null ? "<none>" : f.getName()));
                // dump the 12 instructions before the call: r3 = flags is set there
                Address a = r.getFromAddress();
                Listing l = currentProgram.getListing();
                java.util.List<String> pre = new java.util.ArrayList<>();
                Instruction ins = l.getInstructionBefore(a);
                for (int i = 0; i < 14 && ins != null; i++) {
                    pre.add(0, "    " + ins.getAddress() + "  " + ins.toString());
                    ins = l.getInstructionBefore(ins.getAddress());
                }
                for (String p : pre) println(p);
                println("    " + a + "  <CALL mount>");
            }
        }
    }
}
