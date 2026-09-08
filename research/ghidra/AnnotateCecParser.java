// Annotate the HDMI-CEC ingress/parser path with verified facts.
//
// WRITES to the program. Run with GHIDRA_WRITE=1.
//
// Everything asserted in a comment here was read out of the decompiler on
// T-MSMDEUC-1500.9 hdmicec-service (BuildID cb8b3ee8...). Where a bound was
// checked and found sound, that is recorded too -- negative results keep the
// next pass from re-treading the same handler.
//
// Also emits a CEC-PARSER bookmark category so the path is navigable, and
// scans each annotated function's extent for calls to memory sinks, tagging
// the exact call instructions.
//
//@category Samsung.CEC

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class AnnotateCecParser extends GhidraScript {

    private static final String CAT = "CEC-PARSER";

    // entry, label, plate comment
    private static final String[][] NOTES = {
        {"0x8208c", "CCECFileDescriptor::Read",
         "CEC INGRESS -- both physical read paths.\n"
         + "Selected by GetFileDescriptorType():\n"
         + "  type 0 (/dev/micom-cec): read(fd,&buf,0x14) into a 20-byte stack area,\n"
         + "    then gate `if (n - 1U < 0x11)` => accepts 1..17 bytes only. BOUNDED.\n"
         + "  type 1 (/dev/ttyS2 UART): memset(buf,0,0xff); read(fd,buf,0xff) into\n"
         + "    local_124[256], then a byte-at-a-time framing state machine:\n"
         + "      - sync on 0xFF,0xFE\n"
         + "      - expected length = (b0 & 0x1f) + 1   => 1..32\n"
         + "      - bytes accumulate at this[count + 0x15] (object buffer 0x15..0x47, 51 bytes)\n"
         + "      - XOR checksum over this[1..count] must match trailing byte\n"
         + "      - callback fires only when `count - 1 < 0x11` => 1..17. BOUNDED.\n"
         + "Both paths therefore gate the dispatch callback at <= 17 bytes.\n"
         + "NOTE: the UART path is physically reachable (RS-232 / USB serial); SamyGO\n"
         + "reports USB Serial = ON on this generation."},

        {"0x72aac", "CECRx::t_ThreadFunc",
         "CEC RX thread. Drives CCECFileDescriptor::Read and hands complete frames\n"
         + "to CECRx::ReceiveCECMsg via the bound callback at fd+0x54 (arg fd+0x48)."},

        {"0x72c50", "CECRx::ReceiveCECMsg",
         "LATENT DEFECT -- NOT REACHABLE (resolved, see lead-002).\n"
         + "CECRx::ReceiveCECMsg(unsigned char *buf, unsigned char len)\n"
         + "  n = (uint)len;                      // full byte: 0..255\n"
         + "  p = operator_new(0x11, nothrow);    // 17-byte heap allocation\n"
         + "  memcpy(p, buf, n);                  // @0x72d16 -- NO BOUNDS CHECK ON n\n"
         + "The copy is genuinely unguarded: n > 17 would overflow the 17-byte chunk\n"
         + "by up to 238 controlled bytes in a root process. Safety rests entirely\n"
         + "on the callers.\n"
         + "REACHABILITY RESOLVED -- both producers pass the VALIDATED length:\n"
         + "  micom (@0x820c4): subs r3,r0,#1 / cmp r3,#0x10 / bhi  => n in 1..17,\n"
         + "      then strb r0,[r2] stores that same r0 as the length.\n"
         + "  UART  (@0x821be): subs r1,#1 / cmp r1,#0x10 / bhi   => r1 in 1..17,\n"
         + "      and r10 (the stored length, strb.w r10,[r2]) is derived from r1 at\n"
         + "      0x82146 `ands r10,r1,#0xff`, reached only when count == expected\n"
         + "      (expected = (b0 & 0x1f) + 1 <= 32). So checked value == used value.\n"
         + "BINDING RESOLVED: CECRx::CECRx @0x72ec4 calls SetFunctorForRxMsg with a\n"
         + "PC-relative literal resolving to 0x72c51 (Thumb) = ReceiveCECMsg itself.\n"
         + "ReceiveCECMsg has NO other callers (only an EXTERNAL export ref), and\n"
         + "Read has exactly one caller (t_ThreadFunc). The path is closed.\n"
         + "=> Re-open only if another producer ever calls SetFunctorForRxMsg, or a\n"
         + "   future firmware relaxes either gate. The copy stays one edit from bad."},

        {"0x72d84", "CECRx::m_ProcessCECMsg",
         "Main-loop trampoline. NULL-checks, then\n"
         + "CCECMsgReceiver::ProcessInterfaceMsg(recv, frame), then\n"
         + "operator delete(frame, 0x11). Frame object is exactly 17 bytes."},

        {"0x4b4e8", "CCECMsgReceiver::GetDeviceModelNameProcessing",
         "LEAD-001 (see findings/lead-001-getdevicemodelname-overread.md).\n"
         + "Signature takes ONLY CECMessage const& -- no length parameter, unlike\n"
         + "its siblings. Copies a fixed 13 (opcode 0x89) or 10 bytes into an\n"
         + "un-memset char[16], then strlen() it and build a std::string.\n"
         + "=> unterminated-buffer over-read into adjacent stack, captured into\n"
         + "CECStateInfo::SetSoundBarModelName. Read-only; info-disclosure class.\n"
         + "UNCONFIRMED: observable sink for the resulting string not yet traced."},

        {"0x4b704", "CCECMsgReceiver::SetOSDNameProcessing",
         "CHECKED - NOT VULNERABLE. Receives the length and validates it:\n"
         + "  if (len < 2) reject; else if (len < 0x11) { STRNCPY(buf+2, msg+2, len-2);\n"
         + "                                             buf[len] = 0; }\n"
         + "buf is byte[18], so max index 16 stays in bounds (2 bytes slack).\n"
         + "This is the correct pattern; contrast with GetDeviceModelNameProcessing."},

        {"0x45db4", "CCECMsgSender::CECApi_VendorCommand",
         "CHECKED - NOT VULNERABLE, and TX-side (CCECMsgSender), not attacker-facing.\n"
         + "Rejects `0xe < n` before memcpy into the interface message."},

        {"0x45ea4", "CCECMsgSender::CECApi_VendorCommandWithID",
         "CHECKED - NOT VULNERABLE, TX-side. Rejects `0xd < n` before memcpy."},

        {"0x48a9c", "CCECMsgReceiver::ProcessVCReceiverOptionData",
         "CHECKED - NOT VULNERABLE. Uses fortified __snprintf_chk(buf,100,1,100,...)\n"
         + "into a 100-byte stack buffer that is memset first."},
    };

    // Sinks worth tagging at the exact call instruction.
    private static final Set<String> SINKS = new HashSet<>(Arrays.asList(
        "memcpy", "memmove", "strncpy", "strncat", "strlen", "read", "malloc",
        "_Znaj", "_Znwj", "operator_new", "__snprintf_chk", "STRNCPY", "MEMCPY"));

    @Override
    public void run() throws Exception {
        int plates = 0, marks = 0, calls = 0;

        for (String[] n : NOTES) {
            Address a = addr(n[0]);
            Function f = getFunctionContaining(a);
            if (f == null) {
                println("WARN no function at " + n[0] + " (" + n[1] + ")");
                continue;
            }
            String body = "[" + n[1] + "]\n" + n[2];
            f.setComment(body);
            plates++;
            createBookmark(f.getEntryPoint(), CAT, n[1]);
            marks++;
            calls += tagSinkCalls(f);
            println("annotated " + f.getName() + " @ " + f.getEntryPoint());
        }

        defineFrameStruct();

        println("");
        println("plate comments: " + plates + "  bookmarks: " + marks
                + "  sink call sites tagged: " + calls);
    }

    // Walk the function body and put an EOL comment on any call to a sink.
    private int tagSinkCalls(Function f) {
        int n = 0;
        InstructionIterator it =
            currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) {
                continue;
            }
            for (Reference r : ins.getReferencesFrom()) {
                Symbol s = currentProgram.getSymbolTable()
                        .getPrimarySymbol(r.getToAddress());
                if (s == null) {
                    continue;
                }
                String base = s.getName();
                int at = base.indexOf('@');
                if (at > 0) {
                    base = base.substring(0, at);
                }
                if (!SINKS.contains(base)) {
                    continue;
                }
                setEOLComment(ins.getAddress(), "SINK: " + base);
                createBookmark(ins.getAddress(), CAT, "sink " + base
                        + " in " + f.getName());
                n++;
            }
        }
        return n;
    }

    // The 17-byte heap frame that ReceiveCECMsg allocates and ProcessInterfaceMsg
    // consumes. Sizes come from operator_new(0x11) / operator delete(p,0x11).
    private void defineFrameStruct() {
        try {
            StructureDataType s = new StructureDataType(
                    new CategoryPath("/CEC"), "CecFrame", 0);
            s.add(ByteDataType.dataType, 1, "header",
                  "bits 7-4 initiator LA, bits 3-0 destination LA");
            s.add(ByteDataType.dataType, 1, "opcode", "CEC opcode");
            s.add(new ArrayDataType(ByteDataType.dataType, 15, 1), "operands",
                  "operand bytes; 17-byte allocation total");
            currentProgram.getDataTypeManager().addDataType(
                    s, DataTypeConflictHandler.REPLACE_HANDLER);
            println("data type /CEC/CecFrame defined (" + s.getLength() + " bytes)");
        } catch (Exception e) {
            println("WARN could not define CecFrame: " + e);
        }
    }

    private Address addr(String hex) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseLong(hex.substring(2), 16));
    }
}
