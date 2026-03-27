# Initial Simulator

_2026-02-19_

## What happened

Built a hardware-level simulator that runs the unmodified firmware binary. Rather than porting the decompiled C, this approach uses [jarikomppa/emu8051](https://github.com/jarikomppa/emu8051) as the CPU core and implements the MMT-8 peripheral hardware in C around it. SDL2 renders the LCD, buttons, and LEDs.

The key insight with emu8051 is that it exposes function-pointer callbacks for external memory reads/writes and SFR access — exactly the seam needed to intercept I/O. The hardware emulation (`mmt8_hw.c`) handles HC138 address decoding, the HD44780 LCD state machine, and the keyboard matrix scanner. The GUI (`mmt8_gui.c`) renders an 820×500 window approximating the MMT-8 front panel with amber LCD text, track LEDs, and clickable buttons.

One critical patch was required: the upstream emu8051 implements `MOVX @Ri` using only the 8-bit Ri value as the address. The 8051 spec says P2 is the high address byte, making it a 16-bit `P2:Ri` address. The MMT-8 firmware relies on this heavily — it writes a page number to P2 then uses `MOVX @R0` to walk through 256-byte pages in XDATA. Without this patch the firmware can't access external RAM and hangs at boot. Four opcodes patched in `opcodes.c` (0xE2, 0xE3, 0xF2, 0xF3).

Status: the firmware boots correctly and the LCD displays the startup splash (`* ALESIS MMT-8 * / * VERSION 1.11 *`) and transitions to the main screen. Button matrix mapping is approximate — the column/row assignments are educated guesses from firmware analysis that need trial-and-error refinement against the running firmware. No MIDI I/O yet.

Timing is wall-clock based: the 80C31 runs at 1 MHz machine cycle rate (12 MHz / 12), and the main loop measures real elapsed time and executes the equivalent number of `tick()` calls, capped at 50,000 per frame to prevent spiral-of-death if the host gets behind.

---

_commit: 8ac8913_
