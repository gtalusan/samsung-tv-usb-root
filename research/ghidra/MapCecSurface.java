// Map the HDMI-CEC attack surface of a stripped Tizen service binary.
//
// Read-only. Emits three sections:
//   [DEV]   references to device nodes / CEC-related strings, with the
//           containing function -- entry points into the CEC data path.
//   [SINK]  callers of memory/string sinks reachable from untrusted CEC frames.
//   [STATS] function inventory, largest functions first.
//
// Nothing here renames or annotates; annotation belongs in a separate,
// explicitly writable pass.
//
//@category Samsung.CEC

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

public class MapCecSurface extends GhidraScript {

    // Sinks worth knowing the callers of when the input is an attacker-shaped
    // CEC frame (length byte + payload).
    private static final Set<String> SINKS = new LinkedHashSet<>(Arrays.asList(
        "memcpy", "memmove", "memset", "strncpy", "strncat", "strcpy", "strcat",
        "sprintf", "snprintf", "strlen", "strstr", "strdup", "read", "ioctl",
        "malloc", "free", "_Znaj", "_Znwj"));

    private static final String[] STR_PATTERNS = {
        "/dev/", "cec", "CEC", "micom", "Cec", "opcode", "Opcode", "logical",
        "physical", "vendor", "osd", "OSD", "routing"
    };

    @Override
    public void run() throws Exception {
        Program p = currentProgram;
        println("program: " + p.getName() + "  " + p.getLanguageID()
                + "  imageBase=" + p.getImageBase());

        FunctionManager fm = p.getFunctionManager();
        ReferenceManager rm = p.getReferenceManager();

        // ---- [DEV] interesting strings and who references them -------------
        println("");
        println("=== [DEV] CEC / device string references ===");
        int shown = 0;
        DataIterator data = p.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data d = data.next();
            String repr = StringDataInstance.getStringDataInstance(d).getStringValue();
            if (repr == null || repr.length() < 3 || repr.length() > 120) {
                continue;
            }
            boolean hit = false;
            for (String pat : STR_PATTERNS) {
                if (repr.contains(pat)) { hit = true; break; }
            }
            if (!hit) {
                continue;
            }
            Reference[] refs = getReferencesTo(d.getAddress());
            if (refs.length == 0) {
                continue;
            }
            StringBuilder sb = new StringBuilder();
            for (Reference r : refs) {
                Function f = fm.getFunctionContaining(r.getFromAddress());
                sb.append(" <- ").append(f == null ? r.getFromAddress().toString()
                                                   : f.getName() + "@" + f.getEntryPoint());
            }
            println(String.format("%-40s %s%s", escape(repr), d.getAddress(), sb));
            shown++;
        }
        println("(" + shown + " referenced strings matched)");

        // ---- [SINK] callers of memory/string sinks -------------------------
        println("");
        println("=== [SINK] callers of memory/string sinks ===");
        Map<String, List<String>> bySink = new TreeMap<>();
        SymbolIterator syms = p.getSymbolTable().getAllSymbols(true);
        while (syms.hasNext() && !monitor.isCancelled()) {
            Symbol s = syms.next();
            String base = s.getName();
            int at = base.indexOf('@');
            if (at > 0) {
                base = base.substring(0, at);
            }
            if (!SINKS.contains(base)) {
                continue;
            }
            for (Reference r : rm.getReferencesTo(s.getAddress())) {
                Function caller = fm.getFunctionContaining(r.getFromAddress());
                if (caller == null) {
                    continue;
                }
                bySink.computeIfAbsent(base, k -> new ArrayList<>())
                      .add(caller.getName() + "@" + caller.getEntryPoint()
                           + " (call@" + r.getFromAddress() + ")");
            }
        }
        for (Map.Entry<String, List<String>> e : bySink.entrySet()) {
            Set<String> uniq = new LinkedHashSet<>(e.getValue());
            println("-- " + e.getKey() + "  (" + uniq.size() + " call sites)");
            for (String c : uniq) {
                println("     " + c);
            }
        }

        // ---- [STATS] function inventory ------------------------------------
        println("");
        println("=== [STATS] function inventory ===");
        List<Function> fns = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            fns.add(f);
        }
        println("total functions: " + fns.size());
        fns.sort((a, b) -> Long.compare(size(b), size(a)));
        println("largest 25:");
        for (int i = 0; i < Math.min(25, fns.size()); i++) {
            Function f = fns.get(i);
            println(String.format("   %-34s %10s  %6d bytes",
                    f.getName(), f.getEntryPoint(), size(f)));
        }
    }

    private long size(Function f) {
        return f.getBody() == null ? 0 : f.getBody().getNumAddresses();
    }

    private String escape(String s) {
        return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
