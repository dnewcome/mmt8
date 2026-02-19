# MMT-8 Firmware C Port — Implementation Plan

## Goal
Transform the Ghidra-decompiled `mmt8_decompiled.c` into compilable C that runs on Linux, with ncurses LCD display emulation. Input (keyboard/MIDI) deferred to later.

## Architecture Overview

```
mmt8/port/
├── Makefile
├── main.c                 # Entry point, ncurses init, main loop
├── mmt8_hal.h             # Hardware Abstraction Layer (types, macros, memory)
├── mmt8_hal.c             # HAL implementation (XDATA, IRAM, SFRs, I/O)
├── lcd_emu.h              # ncurses LCD emulation interface
├── lcd_emu.c              # HD44780 LCD emulation via ncurses
├── mmt8_core.c            # Transformed firmware logic (from mmt8_decompiled.c)
└── mmt8_core.h            # Function declarations for core firmware
```

## Step 1: HAL Layer (`mmt8_hal.h` / `mmt8_hal.c`)

Replace all 8051 hardware with C abstractions:

- **Memory arrays**: `uint8_t XDATA[65536]`, `uint8_t IRAM[256]`, `uint8_t CODE[32768]`
- **SFR variables**: `uint8_t P0, P1, P2, P3, SP, TMOD, TCON, SCON, IE, IP, TH0, TL0, TH1, TL1, PSW, ACC, B, SBUF, PCON, DPH, DPL`
- **P2 page access macros**:
  - `MOVX_AT_R0_READ(r0)` → `XDATA[(P2 << 8) | (r0)]`
  - `MOVX_AT_R0_WRITE(r0, val)` → `XDATA[(P2 << 8) | (r0)] = (val)`
  - `MOVX_AT_DPTR_READ()` → `XDATA[(DPH << 8) | DPL]`
  - `MOVX_AT_DPTR_WRITE(val)` → `XDATA[(DPH << 8) | DPL] = (val)`
- **Bit-addressable flags**: Map the ~56 bit flags (`_c_0` through `_f_7`, addresses 0x20-0x2F) to a `uint8_t bit_area[16]` array with `BIT_GET(addr, bit)` / `BIT_SET(addr, bit)` macros, or individual `bool` variables where names are clear
- **IRAM named variables**: `#define` for all 42 documented IRAM locations (e.g., `#define tick_counter IRAM[0x7D]`)
- **I/O port access**: Functions `io_write(addr, val)` and `io_read(addr)` that dispatch based on address:
  - `0xFF00` (LED_CONTROL) → no-op or debug log
  - `0xFF02` (LED_DATA) → no-op or debug log
  - `0xFF04` (STATUS_LATCH) → no-op or debug log
  - `0xFF06` (KEY_COLUMN_SEL) → no-op (input deferred)
  - `0xFF08` (LCD_CMD_DATA) → route to LCD emulation
  - `0xFF0E` (TRANSPORT_STATE) → store state variable
  - `0xFF0F` (BEAT_DIVIDER) → store value
  - `0xFF1A` (CLICK_ENABLE) → store value
- **Ghidra macro replacements**:
  - `CONCAT11(hi, lo)` → `((uint16_t)(hi) << 8) | (lo)`
  - `SUB21(val16, val8)` → `(uint16_t)((val16) - (val8))`
  - `ZEXT12(val8)` → `(uint16_t)(val8)`
  - `CARRY1(a, b)` → `((uint16_t)(a) + (uint16_t)(b) > 0xFF)`
- **Register bank handling**: The ISR register bank switching becomes no-ops since we won't have real interrupts. R0-R7 become regular local variables in each function.
- **Timer/interrupt stubs**: `timer0_isr()`, `serial_isr()`, etc. become callable functions invoked from the main loop on a timer basis (using `clock_gettime` or similar).
- **Load CODE ROM**: Read `alesis_mmt8_v111.bin` into the `CODE[]` array at startup (needed for `copy_code_to_xdata` and string data).

## Step 2: LCD Emulation (`lcd_emu.h` / `lcd_emu.c`)

Emulate HD44780 2-line LCD via ncurses:

- Internal state: 2×40 character DDRAM buffer, cursor position, entry mode, display on/off
- `lcd_write_command(cmd)`: Handle HD44780 commands:
  - `0x01`: Clear display
  - `0x02`: Return home
  - `0x06`: Entry mode (increment, no shift)
  - `0x0E`/`0x0C`: Display on, cursor on/off
  - `0x38`: 8-bit mode, 2-line
  - `0x80+addr`: Set DDRAM address (line 1: 0x00-0x27, line 2: 0x40-0x67)
- `lcd_write_data(ch)`: Write character at cursor, advance cursor
- `lcd_read_busy()`: Always return not-busy (no timing constraints on Linux)
- ncurses rendering: Dedicated window (e.g., 2 rows × 16 cols) drawn with `box()`, updated on each write. Use `mvwaddch()` for character placement.

## Step 3: Transform Firmware Logic (`mmt8_core.c`)

Manual + scripted transformation of `mmt8_decompiled.c`:

### Phase A — Mechanical substitutions (can be scripted in Python):
1. Replace `undefined1` → `uint8_t`, `undefined2` → `uint16_t`
2. Replace `DAT_IRAM_XX` references → named IRAM macros from HAL
3. Replace `DAT_EXTMEM_XXXX` → `XDATA[0xXXXX]`
4. Replace MOVX patterns → HAL macros
5. Replace `CONCAT11`, `SUB21`, `ZEXT12`, `CARRY1` → HAL macros
6. Strip register bank switching (`PSW = 0x10`, etc.) → comments/no-ops
7. Replace SFR direct access (`P0`, `P1`, `SCON`, etc.) → HAL variables
8. Replace I/O port writes (`DAT_EXTMEM_FF00 = val`) → `io_write(0xFF00, val)`

### Phase B — Manual fixups:
1. Convert ISRs to regular functions callable from main loop
2. Fix `lcd_print_string` / `lcd_write_string_inline` which read from CODE memory using inline return-address tricks (8051 idiom: LCALL to string, string follows, RET pops past it) — replace with explicit string pointers into CODE[] array
3. Handle the 4 indirect jumps identified by dis51
4. Verify pointer arithmetic (8051 uses 8-bit and 16-bit pointers mixed)
5. Fix any decompiler artifacts in control flow

## Step 4: Main Entry Point (`main.c`)

```c
int main(int argc, char *argv[]) {
    // Init ncurses
    initscr(); cbreak(); noecho(); nodelay(stdscr, TRUE);

    // Create LCD window
    lcd_emu_init();

    // Load ROM into CODE[]
    hal_init("alesis_mmt8_v111.bin");

    // Run firmware init (equivalent to RESET vector handler)
    main_init();

    // Main loop (simplified — no real interrupts)
    while (1) {
        // Simulate timer tick based on wall clock
        hal_tick();

        // Run one iteration of main event loop
        main_loop_iteration();

        // Refresh ncurses display
        lcd_emu_refresh();

        // Small sleep to avoid burning CPU
        usleep(1000);  // ~1ms
    }

    endwin();
    return 0;
}
```

## Step 5: Build System (`Makefile`)

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -lncurses
SRCS = main.c mmt8_hal.c lcd_emu.c mmt8_core.c
TARGET = mmt8_emu

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
```

## Implementation Order

1. **mmt8_hal.h/c** — Memory arrays, SFR variables, macros, I/O dispatch, ROM loader
2. **lcd_emu.h/c** — HD44780 emulation with ncurses rendering
3. **mmt8_core.h/c** — Transform decompiled code using Python script for mechanical substitutions, then manual fixup
4. **main.c** — Entry point wiring everything together
5. **Makefile** — Build system
6. **Compile and iterate** — Fix compiler errors, test LCD output

## Key Risks / Notes

- The `sequence_playback_engine` (1513 bytes, calls ~25 functions) is the most complex function and will need the most manual attention
- String handling via 8051 LCALL/RET tricks needs careful manual conversion
- Without real interrupts, timing will be approximate (wall-clock based)
- Input is deferred — keyboard scan returns "no keys pressed" (P1=0xFF), MIDI input buffer stays empty
- The CODE[] array must be populated from the binary for `copy_code_to_xdata` to work (it copies default data tables from ROM to RAM)
