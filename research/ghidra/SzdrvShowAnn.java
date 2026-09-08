//@category Samsung.SZDRV
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
public class SzdrvShowAnn extends GhidraScript {
    @Override public void run() throws Exception {
        int b=0;
        java.util.Iterator<Bookmark> it = currentProgram.getBookmarkManager().getBookmarksIterator("Note");
        while (it.hasNext()) { Bookmark bm=it.next();
            if (!"SZDRV".equals(bm.getCategory())) continue;
            println("BOOKMARK "+bm.getAddress()+"  "+bm.getComment()); b++; }
        println("SZDRV bookmarks: "+b);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String c=f.getComment();
            if (c!=null && c.contains("OFF-BY-ONE")) { println("PLATE @"+f.getEntryPoint()+" "+f.getName()); }
        }
    }
}
