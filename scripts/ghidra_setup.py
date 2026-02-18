# Pre-analysis script: set up 8051 entry points and disassemble
#@category Analysis
#@runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd

addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

# 8051 interrupt vector addresses
VECTORS = [0x0000, 0x0003, 0x000B, 0x0013, 0x001B, 0x0023]

VECTOR_NAMES = {
    0x0000: "RESET_vector",
    0x0003: "EXT_INT0_isr",
    0x000B: "TIMER0_isr",
    0x0013: "EXT_INT1_isr",
    0x001B: "TIMER1_isr",
    0x0023: "SERIAL_isr",
}

# Step 1: Disassemble from all interrupt vectors
print("Disassembling from interrupt vectors...")
for vec in VECTORS:
    addr = addr_space.getAddress(vec)
    cmd = DisassembleCommand(addr, None, True)
    cmd.applyTo(currentProgram)
    print("  Disassembled from 0x%04X" % vec)

# Step 2: Follow LJMP targets and disassemble those too
print("Following LJMP targets...")
for vec in VECTORS:
    addr = addr_space.getAddress(vec)
    inst = listing.getInstructionAt(addr)
    if inst and "LJMP" in inst.getMnemonicString():
        refs = inst.getOperandReferences(0)
        if len(refs) > 0:
            target = refs[0].getToAddress()
            cmd = DisassembleCommand(target, None, True)
            cmd.applyTo(currentProgram)
            print("  Followed LJMP at 0x%04X -> 0x%04X" % (vec, target.getOffset()))

# Step 3: Create functions at vector entries and their targets
print("Creating functions...")
for vec in VECTORS:
    addr = addr_space.getAddress(vec)
    inst = listing.getInstructionAt(addr)
    if inst is None:
        continue

    # If the vector is an LJMP, create function at the target
    if "LJMP" in inst.getMnemonicString():
        refs = inst.getOperandReferences(0)
        if len(refs) > 0:
            target = refs[0].getToAddress()
            if fm.getFunctionAt(target) is None:
                cmd = CreateFunctionCmd(target)
                cmd.applyTo(currentProgram)
            func = fm.getFunctionAt(target)
            if func and vec in VECTOR_NAMES:
                func.setName(VECTOR_NAMES[vec], SourceType.USER_DEFINED)
                print("  Created function %s at 0x%04X (from vector 0x%04X)" % (
                    VECTOR_NAMES[vec], target.getOffset(), vec))
    else:
        # Inline handler at the vector address
        if fm.getFunctionAt(addr) is None:
            cmd = CreateFunctionCmd(addr)
            cmd.applyTo(currentProgram)
        func = fm.getFunctionAt(addr)
        if func and vec in VECTOR_NAMES:
            func.setName(VECTOR_NAMES[vec], SourceType.USER_DEFINED)
            print("  Created function %s at 0x%04X" % (VECTOR_NAMES[vec], vec))

# Step 4: Scan for undiscovered code - look for LCALL/ACALL targets
# and disassemble/create functions at them
print("Scanning for call targets...")
new_funcs = 0
passes = 0
while passes < 10:
    passes += 1
    found_new = False
    min_addr = currentProgram.getMinAddress()
    max_addr = currentProgram.getMaxAddress()
    inst_iter = listing.getInstructions(min_addr, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnem = inst.getMnemonicString()
        if "CALL" in mnem or "LCALL" in mnem or "ACALL" in mnem:
            refs = inst.getOperandReferences(0)
            for ref in refs:
                target = ref.getToAddress()
                if listing.getInstructionAt(target) is None:
                    cmd = DisassembleCommand(target, None, True)
                    cmd.applyTo(currentProgram)
                    found_new = True
                if fm.getFunctionAt(target) is None:
                    cmd = CreateFunctionCmd(target)
                    cmd.applyTo(currentProgram)
                    new_funcs += 1
                    found_new = True
    if not found_new:
        break

print("  Created %d additional functions in %d passes" % (new_funcs, passes))

# Step 5: Final count
count = 0
funcs = fm.getFunctions(True)
for f in funcs:
    count += 1
print("Total functions identified: %d" % count)
print("Setup complete!")
