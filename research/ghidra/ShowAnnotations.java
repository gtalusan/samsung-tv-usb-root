// Read back CEC-PARSER annotations to confirm they persisted.
//@category Samsung.CEC
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;

public class ShowAnnotations extends GhidraScript {
    @Override
    public void run() throws Exception {
        int b = 0;
        java.util.Iterator<Bookmark> it =
            currentProgram.getBookmarkManager().getBookmarksIterator("Note");
        while (it.hasNext()) {
            Bookmark bm = it.next();
            if (!"CEC-PARSER".equals(bm.getCategory())) { continue; }
            println("BOOKMARK " + bm.getAddress() + "  " + bm.getComment());
            b++;
        }
        println("bookmarks found: " + b);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String c = f.getComment();
            if (c != null && c.contains("REACHABILITY RESOLVED")) {
                println("");
                println("PLATE @ " + f.getEntryPoint() + " (" + f.getName() + "):");
                println(c);
            }
        }
        println("CecFrame type: " + currentProgram.getDataTypeManager()
                .getDataType("/CEC/CecFrame"));
    }
}
