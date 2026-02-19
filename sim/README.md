# MMT-8 Simulator

A hardware-level simulator for the **Alesis MMT-8 MIDI sequencer**. It runs the
unmodified original firmware binary (`alesis_mmt8_v111.bin`) on an 8051 CPU
emulator, with custom C code implementing the RAM, address decoding, and I/O
multiplexing logic from the schematic. SDL2 provides a GUI showing the LCD
display and clickable buttons matching the real hardware layout.

## Building

### Dependencies

- GCC
- SDL2 development libraries (`libsdl2-dev`)
- SDL2_ttf development libraries (`libsdl2-ttf-dev`)

On Debian/Ubuntu:

```
sudo apt install libsdl2-dev libsdl2-ttf-dev
```

### Compile

```
cd sim
make
```

This produces the `mmt8sim` executable.

### Run

```
./mmt8sim                              # uses ../firmware/alesis_mmt8_v111.bin
./mmt8sim /path/to/alesis_mmt8_v111.bin  # explicit path
```

Press **Escape** or close the window to exit.

## Architecture

```
sim/
├── Makefile          Build system
├── main.c            SDL init, main loop, timing, event dispatch
├── emu8051.h         emu8051 header (jarikomppa/emu8051, patched)
├── core.c            emu8051 core
├── opcodes.c         emu8051 opcodes (patched: MOVX @Ri uses P2)
├── disasm.c          emu8051 disassembler
├── mmt8_hw.h         Hardware emulation interface
├── mmt8_hw.c         Address decode, RAM, I/O latches, keyboard matrix, LCD
├── mmt8_gui.h        SDL GUI interface
└── mmt8_gui.c        SDL rendering: LCD, buttons, LEDs, mouse input
```

### Data flow

```
┌──────────────────────────────────────────────────────────────────┐
│ main.c  –  main loop                                            │
│   tick(&cpu)  →  emu8051 executes one machine cycle              │
│                    ├─ CODE read  → cpu.mCodeMem (32 KB ROM)      │
│                    ├─ XDATA r/w  → mmt8_hw callbacks             │
│                    └─ SFR read   → mmt8_hw P1 callback           │
│   SDL_PollEvent   →  mmt8_gui  →  key_matrix updates            │
│   gui_render      →  reads LCD/LED state from mmt8_hw            │
└──────────────────────────────────────────────────────────────────┘
```

## Design Details

### CPU Emulation (emu8051)

The emulator core is [jarikomppa/emu8051](https://github.com/jarikomppa/emu8051),
a cycle-accurate 8051 emulator in C. It provides function-pointer callbacks for
external memory reads/writes and SFR register access, which is exactly what we
need to intercept I/O.

**Critical patch — MOVX @R0/@R1 must use P2 as high address byte.**
The 8051 specification says `MOVX A,@Ri` and `MOVX @Ri,A` use `P2:Ri` as the
16-bit external data address (P2 = high byte, Ri = low byte). The MMT-8 firmware
relies on this extensively for XDATA page selection — it writes a page number to
P2 then uses `MOVX @R0` to access bytes within that page. The upstream emu8051
only uses the 8-bit Ri value, so opcodes 0xE2, 0xE3, 0xF2, and 0xF3 are patched
in `opcodes.c`:

```c
// Before (upstream): address = Ri only
uint16_t address = INDIR_RX_ADDRESS;

// After (patched): address = P2:Ri
uint16_t address = (aCPU->mSFR[REG_P2] << 8) | INDIR_RX_ADDRESS;
```

Without this patch the firmware cannot access external RAM correctly and will not
boot.

**Firmware loading.** The 32 KB ROM image is loaded directly into `mCodeMem` via
`fread()` (raw binary, not Intel HEX).

**Memory map:**
| Region | Size | Backing |
|--------|------|---------|
| CODE (27C256 EPROM) | 32 KB | `cpu.mCodeMem` |
| XDATA (two 61256 SRAMs) | 64 KB | `cpu.mExtData` |
| Internal RAM (80C31) | 256 B | `cpu.mLowerData` + `cpu.mUpperData` |

### Hardware Emulation (`mmt8_hw.c`)

This module emulates the address decoding, I/O latches, LCD controller, and
keyboard scanner from the MMT-8 schematic.

#### Address Decoding (HC138 U5)

The HC138 decodes XDATA writes in the 0xFF00–0xFF1F range. Address bit A0
serves as the LCD RS pin. Normal SRAM occupies 0x0000–0xFEFF.

| Address  | Device       | Direction  | Function                     |
|----------|-------------|------------|------------------------------|
| `0xFF00` | U6 HC574    | Write      | LED control latch            |
| `0xFF02` | U6 HC574    | Write      | LED data (track LEDs)        |
| `0xFF04` | U7 HC574    | Read/Write | Status/mode output latch     |
| `0xFF06` | U8 HC574    | Write      | Keyboard column select       |
| `0xFF08` | LCD HD44780 | Write      | LCD command register (RS=0)  |
| `0xFF09` | LCD HD44780 | Write      | LCD data register (RS=1)     |
| `0xFF0E` |             | Read/Write | Transport state              |
| `0xFF0F` |             | Read/Write | Beat divider                 |
| `0xFF1A` |             | Read/Write | Click enable                 |

Reads/writes below 0xFF00 pass through to `cpu.mExtData[]` (SRAM).

#### HD44780 LCD Emulation

The LCD is emulated as a state machine tracking:

- `ddram[2][40]` — character buffer (2 lines x 40 characters each)
- `cursor_addr` — current DDRAM write position
- `display_on`, `cursor_on`, `blink_on` — display control flags
- `entry_increment` — cursor direction after write (1 = right, 0 = left)

**Command handling** (RS=0, write to 0xFF08):

| Command      | Action                                      |
|-------------|---------------------------------------------|
| `0x01`      | Clear display, cursor to 0                   |
| `0x02`      | Return home (cursor to 0)                    |
| `0x04–0x07` | Entry mode set (increment/decrement)         |
| `0x08–0x0F` | Display on/off, cursor on/off, blink on/off  |
| `0x20–0x3F` | Function set (accepted, 8-bit 2-line mode)   |
| `0x80+addr` | Set DDRAM address (line 1: 0x00+, line 2: 0x40+) |

**Data handling** (RS=1, write to 0xFF09):
Write character at cursor position, then advance cursor per entry mode.

The visible display is the first 16 characters of each line.

#### Keyboard Matrix (6 columns x 8 rows)

The keyboard scanner in the firmware:
1. Writes a column select byte to 0xFF06 (one bit low = that column active)
2. Reads P1 to get the row state (pressed keys pull bits low)

The column select pattern rotates through 0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF
(bits 0–5 active-low). A pre-check writes 0x80 to detect if any key is pressed
before scanning individual columns.

The P1 SFR read callback implements this:

```c
uint8_t mmt8_p1_read(struct em8051 *cpu, uint8_t reg) {
    uint8_t result = 0xFF;
    for (int col = 0; col < 6; col++) {
        if (!(key_column_sel & (1 << col)))
            result &= ~key_matrix[col];
    }
    return result;
}
```

Mouse clicks in the GUI set/clear bits in `key_matrix[]`, which the firmware
reads during its normal scan cycle.

**Button mapping.** The initial column/row assignments are best-guesses from
firmware analysis. They may need refinement by testing with the running firmware
— press each button and observe whether the firmware responds. The mapping is
defined in `mmt8_gui.c:init_buttons()`.

### GUI (`mmt8_gui.c`)

The GUI renders an 820x500 window using SDL2 + SDL2_ttf:

- **LCD display**: Amber text (#FFAA00) on dark background (#332200) in a
  bordered rectangle. Monospace font, 2 lines x 16 characters.
- **Buttons**: Rectangles with text labels arranged to approximate the MMT-8
  front panel. Darken on press.
- **LEDs**: Small colored squares above buttons that have indicators. Green for
  most functions, red for REC. LED state is read from the `led_data` latch
  written by the firmware.
- **Font discovery**: Tries several common monospace font paths
  (DejaVu Sans Mono, Liberation Mono, FreeMono). Falls back to no text if none
  found.

Button groups on the panel:
- **Mode**: PART, EDIT, SONG, NAME (with LEDs on first three)
- **Function**: CLICK, COPY, ERASE, TEMPO, LOOP, ECHO, LENGTH, MERGE, QUANT,
  TRANS, FILTER, MIDI CH, CLOCK, TAPE
- **Track**: 1–8 (with green LEDs)
- **Numeric keypad**: 0–9, +, -
- **Transport**: <<, >>, PLAY (LED), STOP, REC (red LED)

### Main Loop (`main.c`)

The 80C31 runs at 12 MHz with a divide-by-12 clock, giving 1,000,000 machine
cycles per second. Each `tick()` executes one machine cycle.

The main loop:
1. Measures real elapsed time via `SDL_GetPerformanceCounter()`
2. Converts to machine cycles (1 cycle = 1 microsecond)
3. Caps at 50,000 cycles per frame to prevent spiral-of-death
4. Executes that many `tick()` calls
5. Polls SDL events (mouse clicks update `key_matrix`)
6. Renders the GUI (~60 FPS with vsync + `SDL_Delay(1)`)

A one-shot debug dump prints the LCD contents to stdout after 500,000 cycles to
verify the firmware booted correctly.

## Verification

On first run, the LCD should display the startup screen:

```
* ALESIS MMT-8 *
* VERSION 1.11 *
```

After the splash delay, it transitions to:

```
SELECT PART  00
" NO PART NAME "
```

## Known Limitations and Future Work

- **Keyboard matrix mapping** is approximate. The column/row assignments in
  `init_buttons()` are educated guesses and will need trial-and-error refinement
  with the running firmware to get each button mapped to its correct function.
- **MIDI I/O** is not implemented. The UART (Timer 1 baud rate generator, SBUF)
  could be connected to system MIDI ports in the future.
- **Timer/interrupt accuracy** — emu8051's built-in timer handling covers
  Timer 0 (sequencer clock) and Timer 1 (MIDI baud rate), but EXT_INT0 (used
  for external sync) may need manual triggering if external clock sync is
  desired.
- **LCD read-back** is not implemented (the firmware doesn't appear to read the
  busy flag — it uses software delay loops instead).
- **LED control register** (`0xFF00`) is captured but not yet fully decoded for
  display. Currently only `led_data` (`0xFF02`) drives the GUI LEDs.
- **No CGRAM** — custom character definitions are not implemented in the LCD
  emulation, so any custom glyphs will display as spaces.
