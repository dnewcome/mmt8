# Disassembly and Decompilation

_2026-02-18_

## What happened

Started by dumping the EPROM from the MMT-8 — 32KB 27C256, straight binary read. Used `dis51` to get an initial assembly listing (29,208 lines), then brought it into Ghidra 12.0 for decompilation and annotation.

Wrote three Ghidra Jython scripts to automate the tedious parts: `ghidra_setup.py` seeds the disassembly from known entry points (reset vector, interrupt vectors), `ghidra_annotate.py` applies function names, IRAM variable labels, and I/O port comments from my analysis, and `ghidra_export.py` dumps decompiled C, a function list with addresses and sizes, and a call graph.

The decompiled output is 7,924 lines of C pseudocode across 108 functions. The largest is `sequence_playback_engine` at 1,513 bytes, which iterates all 8 tracks and dispatches MIDI events by timestamp — the heart of the thing. The main loop is about 1,000 bytes and runs `scan_keyboard → process_midi_input → sequence_playback_engine → handle_buttons → update_display` in a tight while(1).

The most interesting 8051 idiom I found: string printing via LCALL/RET. The firmware calls a function, then the string bytes immediately follow the call instruction in CODE memory, and the callee reads them using the return address on the stack as a pointer before adjusting SP and returning. Ghidra gets confused by this because the string data looks like code.

Also documented the full memory map, interrupt vectors, IRAM variable layout, and I/O port decode (HC138 driving HC574 latches at 0xFF00–0xFF1F).

---

_commit: f55d457_
