// Read back EXFAT-PARSER annotations to confirm they persisted. Read-only.
//@category Samsung.Exfat
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class ExfatShowAnnotations extends GhidraScript {
    @Override
    public void run() throws Exception {
        int b = 0;
        java.util.Iterator<Bookmark> it =
            currentProgram.getBookmarkManager().getBookmarksIterator("Note");
        while (it.hasNext()) {
            Bookmark bm = it.next();
            if (!"EXFAT-PARSER".equals(bm.getCategory())) { continue; }
            println("BOOKMARK " + bm.getAddress() + "  " + bm.getComment());
            b++;
        }
        println("bookmarks found: " + b);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String c = f.getComment();
            if (c != null && c.contains("LEAD-004 PRIMARY")) {
                println("");
                println("PLATE @ " + f.getEntryPoint() + " (" + f.getName() + "):");
                println(c);
            }
        }
    }
}
