# Ghidra headless post-analysis script for Alesis MMT-8 firmware
# Exports: decompiled C, function list, call graph, xrefs to I/O ports
#@category Analysis
#@runtime Jython

import java.io.FileWriter as FileWriter
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

OUTPUT_DIR = "/home/dan/sandbox/dnewcome/mmt8"
monitor = ConsoleTaskMonitor()

# MMT-8 I/O port addresses (from schematic)
IO_PORTS = {
    0xFF00: "IO_CTRL_0 (HC574 output latch)",
    0xFF04: "IO_CTRL_1 (output latch)",
    0xFF08: "LCD_DATA (HD44780 LCD)",
    0xFF0E: "IO_INPUT_0 (button/status input)",
    0xFF0F: "IO_INPUT_1",
    0xFF1A: "IO_INPUT_2",
}

INTERRUPT_VECTORS = {
    0x0000: "RESET",
    0x0003: "EXT_INT0 (timing tick counter)",
    0x000B: "TIMER0 (reload TH0/TL0, MIDI timing)",
    0x0013: "EXT_INT1 (unused, shares RETI)",
    0x001B: "TIMER1 (UART baud rate)",
    0x0023: "SERIAL (MIDI RX/TX, reg bank 2/3)",
}


def write_file(filename, content):
    path = OUTPUT_DIR + "/" + filename
    fw = FileWriter(path)
    fw.write(content)
    fw.close()
    print("Wrote %s" % path)


def label_interrupt_vectors():
    fm = currentProgram.getFunctionManager()
    ISR_LABELS = {
        0x0000: "RESET_vector",
        0x0003: "EXT_INT0_isr",
        0x000B: "TIMER0_isr",
        0x0013: "EXT_INT1_isr",
        0x001B: "TIMER1_isr",
        0x0023: "SERIAL_isr",
    }
    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    for vec_addr, label in ISR_LABELS.items():
        addr = addr_space.getAddress(vec_addr)
        func = fm.getFunctionAt(addr)
        if func:
            func.setName(label, SourceType.USER_DEFINED)
            print("Labeled 0x%04X as %s" % (vec_addr, label))
        else:
            inst = currentProgram.getListing().getInstructionAt(addr)
            if inst and "LJMP" in inst.getMnemonicString():
                refs = inst.getOperandReferences(0)
                if len(refs) > 0:
                    target = refs[0].getToAddress()
                    target_func = fm.getFunctionAt(target)
                    if target_func:
                        target_func.setName(label, SourceType.USER_DEFINED)
                        print("Labeled 0x%04X -> 0x%04X as %s" % (
                            vec_addr, target.getOffset(), label))


def export_function_list():
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    lines = []
    lines.append("=" * 80)
    lines.append("ALESIS MMT-8 FIRMWARE v1.11 - FUNCTION LIST")
    lines.append("CPU: 80C31 (8051), 12 MHz, External 27C256 EPROM")
    lines.append("=" * 80)
    lines.append("")
    lines.append("%-12s %-8s %-30s %s" % ("Address", "Size", "Name", "Called By"))
    lines.append("-" * 80)

    count = 0
    for func in funcs:
        entry = func.getEntryPoint()
        body = func.getBody()
        size = body.getNumAddresses()
        name = func.getName()
        addr_val = entry.getOffset()

        callers = []
        refs = getReferencesTo(entry)
        for ref in refs:
            caller_func = fm.getFunctionContaining(ref.getFromAddress())
            if caller_func:
                callers.append(caller_func.getName())
        caller_set = list(set(callers))
        caller_str = ", ".join(caller_set[:5]) if caller_set else "(entry/interrupt)"
        if len(caller_set) > 5:
            caller_str += " (+%d)" % (len(caller_set) - 5)

        isr_note = ""
        if addr_val in INTERRUPT_VECTORS:
            isr_note = " [ISR: %s]" % INTERRUPT_VECTORS[addr_val]

        lines.append("%-12s %-8d %-30s %s%s" % (
            entry.toString(), size, name, caller_str, isr_note))
        count += 1

    write_file("mmt8_functions.txt", "\n".join(lines))
    print("Exported %d functions" % count)


def export_call_graph():
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    lines = []
    lines.append("=" * 80)
    lines.append("ALESIS MMT-8 - CALL GRAPH")
    lines.append("=" * 80)
    lines.append("")

    for func in funcs:
        entry = func.getEntryPoint()
        name = func.getName()
        addr_val = entry.getOffset()

        called = set()
        body = func.getBody()
        addr_iter = body.getAddresses(True)
        while addr_iter.hasNext():
            a = addr_iter.next()
            refs = getReferencesFrom(a)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    target_func = fm.getFunctionAt(ref.getToAddress())
                    if target_func:
                        called.add(target_func.getName())

        isr_note = ""
        if addr_val in INTERRUPT_VECTORS:
            isr_note = " [%s]" % INTERRUPT_VECTORS[addr_val]

        lines.append("%s (0x%04X)%s" % (name, addr_val, isr_note))
        if called:
            for c in sorted(called):
                lines.append("    -> %s" % c)
        else:
            lines.append("    (leaf function)")
        lines.append("")

    write_file("mmt8_callgraph.txt", "\n".join(lines))


def export_decompiled_c():
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))

    lines = []
    lines.append("/*")
    lines.append(" * Alesis MMT-8 Firmware v1.11 - Decompiled C Pseudocode")
    lines.append(" * CPU: 80C31 (8051 family), 12 MHz crystal")
    lines.append(" * Generated by Ghidra 12.0")
    lines.append(" *")
    lines.append(" * MEMORY MAP:")
    lines.append(" *   CODE  0x0000-0x7FFF: 27C256 EPROM (program memory)")
    lines.append(" *   XDATA 0x0000-0x7FFF: 61256 SRAM bank 0 (U10)")
    lines.append(" *   XDATA 0x8000-0xFFFF: 61256 SRAM bank 1 (U9)")
    lines.append(" *   IRAM  0x00-0x7F: Internal RAM (direct addressable)")
    lines.append(" *   IRAM  0x80-0xFF: Internal RAM (indirect only)")
    lines.append(" *   SFR   0x80-0xFF: Special Function Registers")
    lines.append(" *")
    lines.append(" * I/O PORTS (memory-mapped in XDATA via HC138 decoder):")
    for addr in sorted(IO_PORTS.keys()):
        lines.append(" *   0x%04X: %s" % (addr, IO_PORTS[addr]))
    lines.append(" *")
    lines.append(" * INTERRUPT VECTORS:")
    for addr in sorted(INTERRUPT_VECTORS.keys()):
        lines.append(" *   0x%04X: %s" % (addr, INTERRUPT_VECTORS[addr]))
    lines.append(" */")
    lines.append("")

    success = 0
    fail = 0
    for func in funcs:
        entry = func.getEntryPoint()
        addr_val = entry.getOffset()

        lines.append("")
        lines.append("/* " + "=" * 70 + " */")
        if addr_val in INTERRUPT_VECTORS:
            lines.append("/* ISR: %s */" % INTERRUPT_VECTORS[addr_val])
        lines.append("/* Function at 0x%04X: %s */" % (addr_val, func.getName()))
        lines.append("/* " + "=" * 70 + " */")

        result = decomp.decompileFunction(func, 60, monitor)
        if result and result.decompileCompleted():
            c_code = result.getDecompiledFunction()
            if c_code:
                lines.append(c_code.getC())
                success += 1
            else:
                lines.append("/* Decompilation produced no output */")
                fail += 1
        else:
            err = "unknown"
            if result:
                err = str(result.getErrorMessage())
            lines.append("/* Decompilation failed: %s */" % err)
            fail += 1

    decomp.dispose()
    write_file("mmt8_decompiled.c", "\n".join(lines))
    print("Decompiled %d functions (%d failed)" % (success, fail))


# === MAIN ===
print("=" * 60)
print("Alesis MMT-8 Firmware Analysis - Ghidra Export")
print("=" * 60)

label_interrupt_vectors()
export_function_list()
export_call_graph()
export_decompiled_c()

print("")
print("All exports complete!")
