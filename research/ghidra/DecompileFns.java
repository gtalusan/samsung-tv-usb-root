// Decompile named/addressed functions to C. Read-only.
//
// Usage: DecompileFns.java <name-or-0xaddr> [more...]
// A bare name matches exactly; a 0x-prefixed argument is an entry point.
//
//@category Samsung.CEC

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFns extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("usage: DecompileFns.java <name-or-0xaddr> [...]");
            return;
        }

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try {
            for (String a : args) {
                for (Function f : resolve(a)) {
                    println("");
                    println("//======================================================");
                    println("// " + f.getName() + " @ " + f.getEntryPoint()
                            + "  (" + f.getBody().getNumAddresses() + " bytes)");
                    println("//======================================================");
                    DecompileResults r = di.decompileFunction(f, 120, monitor);
                    if (r == null || !r.decompileCompleted()) {
                        println("// DECOMPILE FAILED: "
                                + (r == null ? "null" : r.getErrorMessage()));
                        continue;
                    }
                    println(r.getDecompiledFunction().getC());
                }
            }
        } finally {
            di.dispose();
        }
    }

    private List<Function> resolve(String a) {
        List<Function> out = new ArrayList<>();
        if (a.startsWith("0x") || a.startsWith("0X")) {
            Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(Long.parseLong(a.substring(2), 16));
            Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (f == null) {
                f = currentProgram.getFunctionManager().getFunctionContaining(addr);
            }
            if (f != null) {
                out.add(f);
            } else {
                println("// no function at " + a);
            }
            return out;
        }
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(a)) {
                out.add(f);
            }
        }
        if (out.isEmpty()) {
            println("// no function named " + a);
        }
        return out;
    }
}
