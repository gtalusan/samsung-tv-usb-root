// Locate defined strings matching a pattern and report referencing functions.
// Read-only. Args: one or more substrings to match (case-insensitive).
//
//@category Samsung.Ext4

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class Ext4FindString extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] pats = getScriptArgs();
        if (pats.length == 0) {
            println("usage: Ext4FindString.java <substring> [...]");
            return;
        }
        int hits = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            String v = StringDataInstance.getStringDataInstance(d).getStringValue();
            if (v == null || v.length() < 2) {
                continue;
            }
            boolean hit = false;
            for (String p : pats) {
                if (v.toLowerCase().contains(p.toLowerCase())) {
                    hit = true;
                    break;
                }
            }
            if (!hit) {
                continue;
            }
            hits++;
            StringBuilder sb = new StringBuilder();
            for (Reference r : getReferencesTo(d.getAddress())) {
                Function f = getFunctionContaining(r.getFromAddress());
                sb.append("\n      <- ")
                  .append(f == null ? "<no function>" : f.getName())
                  .append(" @ ").append(r.getFromAddress());
            }
            println(String.format("%s  %s%s", d.getAddress(),
                    v.replace("\n", "\\n"),
                    sb.length() == 0 ? "\n      <- (no direct refs)" : sb));
        }
        println("matches: " + hits);
    }
}
