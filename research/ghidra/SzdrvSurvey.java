// Survey load layout + function recovery quality for the szdrv_core module.
//@category Samsung.SZDRV
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;

public class SzdrvSurvey extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program p = currentProgram;
        println("program=" + p.getName() + " lang=" + p.getLanguageID()
                + " imageBase=" + p.getImageBase());
        println("=== MEMORY BLOCKS ===");
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            println(String.format("  %-24s %s..%s size=0x%x %s%s%s init=%s",
                b.getName(), b.getStart(), b.getEnd(), b.getSize(),
                b.isRead()?"r":"-", b.isWrite()?"w":"-", b.isExecute()?"x":"-",
                b.isInitialized()));
        }
        FunctionManager fm = p.getFunctionManager();
        int n=0; long tiny=0;
        for (Function f : fm.getFunctions(true)) { n++; if (f.getBody().getNumAddresses() <= 8) tiny++; }
        println("=== FUNCTIONS: " + n + "  (bodies <=8 bytes: " + tiny + ") ===");
        // count instructions vs defined function bytes in .text
        MemoryBlock text = null;
        for (MemoryBlock b : p.getMemory().getBlocks())
            if (b.getName().contains("text") && b.isExecute() && (text==null || b.getSize()>text.getSize())) text=b;
        if (text != null) {
            long insnBytes = 0;
            InstructionIterator it = p.getListing().getInstructions(
                new AddressSet(text.getStart(), text.getEnd()), true);
            while (it.hasNext()) insnBytes += it.next().getLength();
            long fnBytes = 0;
            for (Function f : fm.getFunctions(true)) {
                if (text.contains(f.getEntryPoint())) fnBytes += f.getBody().getNumAddresses();
            }
            println("  block " + text.getName() + " size=0x" + Long.toHexString(text.getSize())
                    + " instructionBytes=0x" + Long.toHexString(insnBytes)
                    + " functionBodyBytes=0x" + Long.toHexString(fnBytes));
            println("  ORPHANED (insn not in any function) = 0x"
                    + Long.toHexString(insnBytes - fnBytes) + " bytes");
        }
    }
}
