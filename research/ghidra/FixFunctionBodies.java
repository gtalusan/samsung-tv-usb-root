// Recompute truncated function bodies from actual control flow. WRITES.
// Thumb/ARM boundary detection left several CEC functions with bodies that
// stop short, orphaning the code (and the references) that matter.
//@category Samsung.CEC
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class FixFunctionBodies extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address e = toAddr(Long.parseLong(a.substring(2), 16));
            Function f = getFunctionAt(e);
            String name = (f == null) ? null : f.getName();
            long before = (f == null) ? 0 : f.getBody().getNumAddresses();
            if (f != null) {
                removeFunctionAt(e);
            }
            // Recreate with a null body so Ghidra derives it from flow.
            CreateFunctionCmd cmd = new CreateFunctionCmd(name, e, null, SourceType.ANALYSIS, false, true);
            boolean ok = cmd.applyTo(currentProgram, monitor);
            Function nf = getFunctionAt(e);
            println(a + "  " + (name == null ? "?" : name)
                + "  before=" + before
                + "  after=" + (nf == null ? "FAILED" : nf.getBody().getNumAddresses())
                + "  ok=" + ok);
        }
    }
}
