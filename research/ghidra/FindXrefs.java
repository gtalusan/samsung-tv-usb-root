// List all references to the given function entry points. Read-only.
//@category Samsung.CEC
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class FindXrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address ad = toAddr(Long.parseLong(a.substring(2), 16));
            Function f = getFunctionAt(ad);
            println("=== " + a + " " + (f == null ? "(no function)" : f.getName()));
            int n = 0;
            for (Reference r : getReferencesTo(ad)) {
                Function c = getFunctionContaining(r.getFromAddress());
                println("   from " + r.getFromAddress() + " " + r.getReferenceType()
                    + "  in " + (c == null ? "<none>" : c.getName() + "@" + c.getEntryPoint()));
                n++;
            }
            println("   total refs: " + n);
        }
    }
}
