# Ghidra annotation script: rename functions and add comments for Alesis MMT-8
#@category Analysis
#@runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()

# =========================================================================
# FUNCTION RENAMES - derived from behavioral analysis of decompiled output
# =========================================================================
FUNCTION_NAMES = {
    # --- Interrupt Service Routines ---
    0x0003: ("EXT_INT0_isr",
             "External INT0 ISR: increments tick_counter (IRAM 0x7D).\n"
             "Used as timing pulse counter for sequencer clock."),
    0x000B: ("TIMER0_isr",
             "Timer 0 ISR: reloads TH0/TL0 from IRAM 0x7E/0x7F (variable tempo),\n"
             "then increments tick_counter. This is the core MIDI clock source."),
    0x0013: ("EXT_INT1_isr",
             "External INT1 ISR: unused. Just RETI (shared with Timer0 handler)."),
    0x0023: ("SERIAL_isr",
             "UART Serial ISR: handles MIDI RX and TX.\n"
             "Uses register bank 2 (TX) and bank 3 (RX) for fast context switching.\n"
             "RX: reads SBUF into buffer via @R1 (bank3), disables ES when buffer full.\n"
             "TX: sends next byte from buffer via @R0 (bank2), sets _c_4 when done.\n"
             "P2 saved/restored via IRAM 0x5C to preserve XDATA page context."),

    # --- Initialization ---
    0x00FB: ("main_init_and_loop",
             "RESET entry point. Contains hardware init AND main event loop.\n"
             "INIT: SP=0x2F, TMOD=0x21 (T0=mode1/16bit, T1=mode2/autoreload),\n"
             "  TCON=0x51 (T0/T1 running), SCON=0x70 (UART mode1, REN),\n"
             "  TH1=TL1=0xFF (31.25kbaud MIDI baud rate at 12MHz),\n"
             "  IP=0x01 (EXT_INT0 high priority).\n"
             "  Clears IRAM 0x02-0x7F, inits LCD (HD44780), scans keyboard for\n"
             "  boot mode (normal vs self-test vs data integrity check).\n"
             "MAIN LOOP: scan_keyboard -> process_midi_input -> process_transport ->\n"
             "  sequence_playback_engine -> update_display -> handle button events."),
    0x006D: ("init_sequencer_defaults",
             "Initialize default sequencer parameters in XDATA pages 4 and 5.\n"
             "Page 4 (P2=4): clears 0x00-0xC9, sets tempo/time sig defaults:\n"
             "  0xCF=0x62(tempo), 0xD0=0x06, 0xD1-D4=timer reload values.\n"
             "Page 5 (P2=5): clears buffers 0x00-0xC9 and 0xD8-0xE7,\n"
             "  sets 0x4D5=1, 0x4D6=1, 0x4D9=4, 0x4E3=5, 0x4D8=0x60(96ppqn), 0x4DA=0x78(120bpm)."),

    # --- LCD / Display ---
    0x0653: ("io_settle_delay",
             "6x NOP delay for I/O bus settling time after writing to HC574 latches."),
    0x065A: ("lcd_short_delay",
             "Short delay loop (27 iterations) for HD44780 LCD command timing (~40us)."),
    0x0661: ("lcd_long_delay",
             "Long delay (calls lcd_short_delay 39 times) for LCD power-on init (~4.1ms)."),
    0x0634: ("display_status_message",
             "Display context-sensitive status message on LCD.\n"
             "Selects message string based on button state flags (_2_0, _3_0, _4_0).\n"
             "Calls lcd_print_string with address from CODE memory lookup table."),
    0x315B: ("lcd_clear_line",
             "Clears a line on the LCD display."),
    0x315E: ("lcd_print_string",
             "Print null-terminated string from CODE memory to LCD.\n"
             "Takes DPTR (string address in CODE space) as parameter.\n"
             "Writes character data to LCD at XDATA 0xFF08."),
    0x1ECD: ("display_tempo_info",
             "Display tempo and time signature information on LCD.\n"
             "Called after init and during tempo changes."),
    0x2143: ("display_track_mode_screen",
             "Update LCD for TRACK mode display.\n"
             "Shows current part number, track states, position info.\n"
             "Returns display pointer 0x03C8 for track mode string table."),
    0x2193: ("display_song_mode_screen",
             "Update LCD for SONG mode display.\n"
             "Shows song step, part assignments, position info.\n"
             "Returns display pointer 0x04B7 for song mode string table."),
    0x1C0D: ("update_display_full",
             "Full display update: refreshes all LCD content.\n"
             "Called after mode changes, sequence loads, and transport state changes.\n"
             "Multiple callers across init, playback, and button handlers."),
    0x0FE2: ("update_position_display",
             "Update measure/beat position display on LCD during playback.\n"
             "Shows current position within sequence."),
    0x0FFE: ("handle_loop_display",
             "Update display for loop/repeat mode."),

    # --- Keyboard / Input ---
    0x055E: ("scan_keyboard",
             "Scan 6-column keyboard matrix via HC574 latch.\n"
             "Writes column selects to XDATA 0xFF06, reads rows from P1.\n"
             "Debounces: rejects if >2 keys in any column (sets _d_2).\n"
             "Stores raw scan in IRAM 0x26-0x2B, computes edge-detect\n"
             "  (new keypresses) in IRAM 0x20-0x25 via XOR with previous state.\n"
             "Also reads P3.3 (external start/stop input) into _8_4 flag.\n"
             "Key repeat: auto-repeats after 0x80 ticks if held, then every 0x14 ticks."),
    0x3272: ("check_transport_buttons",
             "Check play/stop/record transport button states.\n"
             "Sets flag bits based on which transport buttons are newly pressed."),

    # --- MIDI I/O ---
    0x0B26: ("process_midi_input",
             "Process incoming MIDI data from serial RX buffer.\n"
             "Called in main loop with register bank 2/3 context (RS1=1, RS0=1).\n"
             "Parses MIDI messages and dispatches to appropriate handlers."),
    0x14C8: ("midi_tx_end_sysex",
             "End current MIDI System Exclusive transmission.\n"
             "Sends F7 (End of SysEx) byte to TX buffer."),
    0x14DD: ("midi_tx_flush_buffer",
             "Flush MIDI TX buffer: ensures all pending bytes are sent.\n"
             "Enables serial interrupt (ES=1), clears register bank (RS1=0)."),
    0x14F0: ("midi_tx_check_buffer_full",
             "Check if MIDI TX buffer is full.\n"
             "Compares write pointer against BANK2_R0 (buffer end).\n"
             "If full, enables ES and waits for space. Used by all MIDI TX functions."),
    0x0CFD: ("midi_tx_note_off",
             "Transmit MIDI Note Off message.\n"
             "Sends note-off to the serial TX buffer for note release.\n"
             "Uses register bank 2 context for buffer access."),
    0x2FB2: ("send_midi_timing_clock",
             "Send MIDI real-time timing clock (0xF8) or other real-time message.\n"
             "Parameter selects message: 0xF8=clock, 0xFA=start, 0xFC=stop."),
    0x15FF: ("send_midi_stop_msg",
             "Send MIDI Stop (0xFC) real-time message.\n"
             "Called when playback stops."),
    0x185D: ("send_midi_song_position",
             "Send MIDI Song Position Pointer message.\n"
             "Transmits current sequence position for external sync."),

    # --- Playback Engine ---
    0x0772: ("start_track_playback",
             "Start playback of current track.\n"
             "Loads track mask from sequence data at XDATA (04CC-related),\n"
             "sets _d_3 (sequence loaded), _c_3 (playing), clears note buffer.\n"
             "Only starts if track has data (04D4 != 0) and track is selected (04CC != 0)."),
    0x076B: ("stop_track_playback",
             "Stop current track playback and clean up.\n"
             "If playing (_c_3): sends all-notes-off via midi_tx_note_off,\n"
             "  clears _c_3, restores position pointers (0x73/0x74), clears track mask.\n"
             "If not playing: checks for auto-stop conditions."),
    0x07AC: ("all_notes_off_cleanup",
             "Send note-off for all active notes and clean up playback state.\n"
             "Iterates through active note table at IRAM 0xBE-0xFD,\n"
             "sends note-off for each, clears _c_3, restores pointers."),
    0x0808: ("clear_track_event_buffers",
             "Clear all track event input buffers in XDATA page 2.\n"
             "Sets P2=2, clears offsets 0x00, 0x1F, 0x34, 0x6B, 0xA2, 0xBB.\n"
             "Clears _f_3 (external trigger flag). Called on stop and mode changes."),
    0x0824: ("advance_playback_position",
             "Advance sequence playback position and update counters.\n"
             "Computes position delta, updates BCD measure/beat counters\n"
             "(IRAM 0x51/0x52) with decimal_adjust for display.\n"
             "Handles sequence boundaries and tempo recalculation."),
    0x0918: ("process_recording_realtime",
             "Process MIDI events for real-time recording.\n"
             "Sets _c_2=1 (realtime mode). Reads incoming MIDI data from\n"
             "track event buffers, timestamps with clock counter,\n"
             "and appends to sequence data in XDATA."),
    0x0922: ("process_recording_step",
             "Process MIDI events for step recording.\n"
             "Sets _c_2=0 (step mode). Similar to realtime but advances\n"
             "position by fixed step size rather than real time."),
    0x0AF5: ("sequence_playback_engine",
             "CORE SEQUENCER PLAYBACK ENGINE (1513 bytes - largest function).\n"
             "Iterates through all 8 tracks, reads timestamped MIDI events\n"
             "from sequence data in XDATA, outputs events whose timestamps\n"
             "match the current playback position.\n\n"
             "MIDI event dispatch based on status byte type (BANK0_R2):\n"
             "  < 0x7A: Note On/Off (status | 0x90/0xB0, channel from track)\n"
             "  = 0x7A: Program Change (status | 0xC0)\n"
             "  = 0x7B: Channel Pressure (status | 0xD0)\n"
             "  = 0x7C: Pitch Bend (status | 0xE0)\n"
             "  = 0x7D: System Exclusive (0xF0 prefix)\n\n"
             "Also handles recording: stores incoming events with timestamps\n"
             "into the sequence buffer for note-on, controller, and sysex data.\n"
             "Active note tracking via IRAM 0xBE-0xFD (32 entries x 2 bytes).\n"
             "MIDI TX uses register bank 2 for buffer management."),

    # --- Transport / Mode Control ---
    0x327A: ("handle_play_button",
             "Handle PLAY button press.\n"
             "Initiates sequence playback from current position."),
    0x347B: ("handle_record_button",
             "Handle RECORD button press.\n"
             "Enters record mode (real-time or step depending on context)."),
    0x357A: ("handle_stop_continue",
             "Handle STOP/CONTINUE button press.\n"
             "Stops playback or continues from paused position."),
    0x3F94: ("handle_copy_function",
             "Handle COPY function button.\n"
             "Copies sequence data between parts/tracks."),
    0x407D: ("handle_delete_function",
             "Handle DELETE function button.\n"
             "Deletes sequence data for selected part/track."),
    0x324C: ("continue_recording_existing",
             "Continue recording into an existing (non-empty) sequence.\n"
             "Appends new MIDI data to existing track data."),
    0x5CAF: ("start_recording_new_sequence",
             "Start recording a new sequence from scratch.\n"
             "Allocates XDATA memory for new sequence data, initializes headers."),
    0x2FD3: ("setup_recording_state",
             "Set up internal state for recording.\n"
             "Initializes recording pointers, buffers, and flags."),
    0x0FB4: ("stop_all_playing_notes",
             "Stop all currently sounding notes.\n"
             "Sends MIDI note-off for all tracked active notes."),
    0x10E8: ("configure_tempo_timer",
             "Configure Timer 0 reload values for current tempo.\n"
             "Computes TH0/TL0 reload from tempo BPM value.\n"
             "Stores reload values in IRAM 0x7E/0x7F for Timer0 ISR."),
    0x15D7: ("handle_sequence_boundary",
             "Handle reaching a sequence boundary (end of part/loop point).\n"
             "Decides whether to loop, advance to next part, or stop."),

    # --- Song Mode ---
    0x47A1: ("init_song_playback",
             "Initialize song mode playback.\n"
             "Sets up song step pointer and loads first part."),
    0x47B2: ("get_song_step_data",
             "Get data for current song step.\n"
             "Reads part assignment from song sequence table in XDATA.\n"
             "Called to advance through song step chain."),
    0x47E1: ("process_midi_realtime_msgs",
             "Process MIDI real-time messages (clock, start, stop, continue).\n"
             "Handles external sync: MIDI clock for tempo slave,\n"
             "start/stop/continue for transport control from external sequencer."),
    0x1CC7: ("handle_song_part_change",
             "Handle transition between parts within a song.\n"
             "Loads next part's sequence data when current part ends."),
    0x1DB4: ("handle_song_completion",
             "Handle song reaching its end.\n"
             "Decides whether to loop song or stop based on settings."),

    # --- Track / Part Management ---
    0x599A: ("handle_track_select_button",
             "Handle track selection button press (tracks 0-7).\n"
             "Selects active track for recording/editing/muting."),
    0x5053: ("handle_tempo_edit_button",
             "Handle tempo editing.\n"
             "Enters tempo edit mode, adjusts BPM value."),
    0x7340: ("handle_midi_channel_filter",
             "Handle MIDI channel/filter settings.\n"
             "Configures per-track MIDI channel assignment and filtering."),
    0x2E9E: ("load_sequence_from_storage",
             "Load a sequence/part from XDATA storage.\n"
             "Reads sequence headers and data pointers from XDATA bank."),
    0x6D90: ("init_metronome_click",
             "Initialize metronome/click output.\n"
             "Sets up click timing based on time signature."),

    # --- Data Transfer / Tape ---
    0x2E2D: ("check_data_transfer_state",
             "Check data transfer (tape/MIDI dump) state.\n"
             "Monitors tape interface and MIDI sysex dump status."),
    0x2E20: ("data_transfer_helper",
             "Helper for data transfer operations."),
    0x623D: ("handle_auto_continue_record",
             "Handle automatic continue into next recording pass.\n"
             "Manages loop recording / overdub continuation."),
    0x6C94: ("process_sysex_data_dump",
             "Process MIDI System Exclusive data dump.\n"
             "Handles bulk data transfer for save/load operations."),
    0x5DA6: ("sysex_dump_engine",
             "System Exclusive dump engine (598 bytes).\n"
             "Manages complete MIDI SysEx data dump for backup/restore.\n"
             "Handles chunked transfer with handshaking."),
    0x6D62: ("sysex_dump_helper",
             "Helper for SysEx dump byte formatting."),
    0x5FFC: ("sysex_dump_checksum",
             "Compute checksum for SysEx data dump block."),

    # --- Utility ---
    0x1E08: ("copy_code_to_xdata",
             "Copy data from CODE memory to XDATA.\n"
             "Takes DPTR as source address in code space.\n"
             "Used to initialize XDATA tables from ROM constants."),
    0x1E76: ("compute_position_delta",
             "Compute delta between two sequence positions.\n"
             "16-bit subtraction for position arithmetic."),
    0x1EA8: ("position_calc_helper",
             "Helper for position calculation."),
    0x1EB8: ("multiply_8bit",
             "8-bit multiply helper for position/timing calculations."),
    0x1756: ("set_default_tempo_values",
             "Set default tempo timer reload values."),
    0x17CA: ("setup_sequence_data_ptrs",
             "Set up DPTR and data pointers for current sequence part.\n"
             "Configures XDATA addresses for sequence read/write."),
    0x17CE: ("init_sequence_part_data",
             "Initialize sequence part data structures.\n"
             "Sets up header, track pointers, and default values for a part."),
    0x1709: ("format_bcd_number",
             "Format a number as BCD for display.\n"
             "Converts binary value to BCD digits for LCD output."),
    0x2106: ("lcd_write_digit",
             "Write a single digit character to LCD."),
    0x2114: ("lcd_write_char",
             "Write a character to LCD display at current position."),
    0x2121: ("lcd_set_cursor",
             "Set LCD cursor position."),
    0x212B: ("lcd_write_space",
             "Write a space character to LCD."),
    0x2130: ("lcd_write_byte_hex",
             "Write a byte value in hex/decimal format to LCD."),
    0x213A: ("lcd_busy_wait",
             "Wait for LCD busy flag to clear before next write."),
    0x21CF: ("format_number_2digit",
             "Format and display a 2-digit number on LCD."),
    0x21EE: ("lcd_write_string_inline",
             "Write an inline string to LCD from code memory."),
    0x222C: ("lcd_write_part_name",
             "Write part/sequence name to LCD display."),
    0x20F1: ("lcd_command",
             "Send a command byte to LCD controller.\n"
             "Writes to XDATA 0xFF08 (LCD register)."),
    0x18A1: ("init_playback_timing",
             "Initialize playback timing parameters.\n"
             "Sets up tempo, time signature, and clock dividers."),
    0x1943: ("compute_tempo_reload",
             "Compute Timer 0 reload values from tempo BPM.\n"
             "Converts BPM to timer period for 96 PPQN resolution."),
    0x1A3B: ("sequence_data_seek",
             "Seek to position in sequence data.\n"
             "Advances data pointer to target timestamp."),
    0x1A60: ("sequence_data_read",
             "Read next event from sequence data."),
    0x1A95: ("sequence_data_operations",
             "Sequence data read/write operations.\n"
             "Manages the sequence data buffer in XDATA."),
    0x1841: ("song_mode_helper",
             "Song mode data initialization helper."),
    0x175A: ("update_part_metadata",
             "Update part metadata (length, track count, etc.).\n"
             "Called after recording or editing operations."),

    # --- Button Handlers ---
    0x2EC8: ("process_playback_buttons",
             "Process button events during active playback.\n"
             "Handles mute/unmute, track select, and other controls\n"
             "while sequencer is running."),
    0x33A9: ("play_button_handler_detail",
             "Detailed play button handler.\n"
             "Manages play/continue logic and external sync."),
    0x3561: ("record_button_setup",
             "Record button setup and validation.\n"
             "Checks if recording is possible and prepares state."),
    0x364D: ("stop_button_handler_detail",
             "Detailed stop button processing.\n"
             "Handles stop vs pause depending on current state."),
    0x4107: ("delete_function_impl",
             "Delete function implementation.\n"
             "Erases sequence data for selected track or part."),
    0x4195: ("delete_confirm",
             "Delete confirmation and execution."),
    0x41A6: ("delete_track_data",
             "Delete a single track's data from a part."),
    0x4C77: ("recalculate_sequence_length",
             "Recalculate sequence length after edit.\n"
             "Updates part length counters after recording or deletion."),
    0x5162: ("tempo_edit_impl",
             "Tempo edit mode implementation.\n"
             "Handles BPM increment/decrement with up/down buttons."),
    0x5AE5: ("track_select_impl",
             "Track select implementation.\n"
             "Switches active track and updates display."),
    0x73E1: ("midi_filter_impl",
             "MIDI channel filter implementation.\n"
             "Sets per-track MIDI channel routing."),
    0x3026: ("sequence_edit_operations",
             "Sequence editing operations (copy, move, merge).\n"
             "Manages bulk data operations between parts."),
    0x30D9: ("memory_block_copy",
             "Copy a block of data in XDATA memory.\n"
             "Used for sequence copy/move operations."),
    0x3104: ("memory_block_insert",
             "Insert space in XDATA memory block.\n"
             "Shifts data to make room for new events."),

    # --- Self-Test (boot diagnostic mode) ---
    0x7C2D: ("selftest_ram_rw",
             "Self-test: RAM read/write test.\n"
             "Writes pattern to XDATA RAM via HC574 latch outputs,\n"
             "reads back and verifies. Tests both 61256 RAM chips."),
    0x7C3C: ("selftest_delay_loop",
             "Self-test: delay loop between test phases."),
    0x7C49: ("selftest_pass_msg",
             "Self-test: display PASS message and continue."),
    0x7C4F: ("selftest_show_message",
             "Self-test: display a test status message on LCD.\n"
             "Takes CODE memory address of message string."),
    0x7C5D: ("selftest_fail_halt",
             "Self-test: display FAIL message and halt.\n"
             "Enters infinite loop on test failure."),

    # --- Timer 1 ISR ---
    0x76B2: ("TIMER1_isr",
             "Timer 1 ISR: UART baud rate generator.\n"
             "Timer 1 in mode 2 (8-bit auto-reload) generates 31.25 kbaud\n"
             "MIDI baud rate. TH1=0xFF at 12MHz = 31.25kbaud.\n"
             "This ISR handles overflow events if any additional\n"
             "Timer1-based timing is needed."),
}


def rename_functions():
    count = 0
    for addr_val, (name, comment) in FUNCTION_NAMES.items():
        addr = addr_space.getAddress(addr_val)
        func = fm.getFunctionAt(addr)
        if func:
            func.setName(name, SourceType.USER_DEFINED)
            func.setComment(comment)
            count += 1
            print("  0x%04X -> %s" % (addr_val, name))
        else:
            # Try to find function containing this address
            func = fm.getFunctionContaining(addr)
            if func:
                func.setName(name, SourceType.USER_DEFINED)
                func.setComment(comment)
                count += 1
                print("  0x%04X -> %s (containing)" % (addr_val, name))
            else:
                print("  0x%04X: no function found!" % addr_val)
    print("Renamed %d functions" % count)


def add_plate_comments():
    """Add plate comments at key addresses for code structure documentation."""
    comments = {
        0x0000: "=== INTERRUPT VECTOR TABLE (0x0000-0x002F) ===\n"
                "8051 vectors: 0x0000=Reset, 0x0003=EXT_INT0, 0x000B=Timer0,\n"
                "0x0013=EXT_INT1, 0x001B=Timer1, 0x0023=Serial\n"
                "Padding between vectors contains ASCII version strings '12345'",
        0x00FB: "=== MAIN INITIALIZATION AND EVENT LOOP ===\n"
                "Hardware: 80C31 @ 12MHz, 27C256 EPROM, 2x 61256 SRAM\n"
                "MIDI: 31.25 kbaud via Timer1 auto-reload (TH1=0xFF)\n"
                "Sequencer: 96 PPQN, Timer0 variable tempo, 8 tracks\n"
                "I/O: HC574 latches for keyboard/LEDs, HD44780 LCD\n"
                "Memory: P2 selects 256-byte XDATA pages (0-5 used)\n"
                "  Page 0: MIDI TX buffer\n"
                "  Page 1: MIDI RX buffer\n"
                "  Page 2: Track event buffers (note on/off/CC queues)\n"
                "  Page 3: Active note tracking\n"
                "  Page 4: Sequence parameters and configuration\n"
                "  Page 5: Song mode data and extended parameters",
    }
    for addr_val, comment in comments.items():
        addr = addr_space.getAddress(addr_val)
        cu = listing.getCodeUnitAt(addr)
        if cu:
            cu.setComment(CodeUnit.PLATE_COMMENT, comment)
            print("  Added plate comment at 0x%04X" % addr_val)


# === IRAM variable labels ===
def label_iram_variables():
    """Add labels to key internal RAM locations."""
    iram_space = currentProgram.getAddressFactory().getAddressSpace("INTMEM")
    if iram_space is None:
        print("INTMEM address space not found, skipping IRAM labels")
        return

    IRAM_LABELS = {
        0x20: "key_edge_col0",
        0x21: "key_edge_col1",
        0x22: "key_edge_col2",
        0x23: "key_edge_col3",
        0x24: "key_edge_col4",
        0x25: "key_edge_col5",
        0x26: "key_scan_col0",
        0x27: "key_scan_col1",
        0x28: "key_scan_col2",
        0x29: "key_scan_col3",
        0x2A: "key_scan_col4",
        0x2B: "key_scan_col5",
        0x48: "last_button_state",
        0x4B: "key_repeat_timer",
        0x4C: "solo_track_num",
        0x4D: "display_ptr_hi",
        0x4E: "display_ptr_lo",
        0x4F: "click_countdown",
        0x50: "tick_subdivider",
        0x51: "measure_bcd_hi",
        0x52: "measure_bcd_lo",
        0x53: "total_measures_hi",
        0x54: "total_measures_lo",
        0x5B: "sysex_byte_count",
        0x5C: "saved_P2_page",
        0x6D: "current_track_idx",
        0x6E: "active_track_mask",
        0x6F: "track_bit_rotate",
        0x70: "track_mute_mask",
        0x71: "seq_start_ptr_lo",
        0x72: "seq_start_ptr_hi",
        0x73: "playback_ptr_lo",
        0x74: "playback_ptr_hi",
        0x75: "record_ptr_hi",
        0x76: "record_ptr_lo",
        0x77: "midi_clock_hi",
        0x78: "midi_clock_lo",
        0x7B: "init_param_a",
        0x7C: "init_param_b",
        0x7D: "tick_counter",
        0x7E: "timer0_reload_hi",
        0x7F: "timer0_reload_lo",
    }
    symtab = currentProgram.getSymbolTable()
    count = 0
    for offset, name in IRAM_LABELS.items():
        addr = iram_space.getAddress(offset)
        try:
            symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            count += 1
        except:
            pass
    print("  Labeled %d IRAM variables" % count)


def label_xdata_io():
    """Add labels to memory-mapped I/O registers."""
    extmem_space = currentProgram.getAddressFactory().getAddressSpace("EXTMEM")
    if extmem_space is None:
        print("EXTMEM address space not found, skipping I/O labels")
        return

    IO_LABELS = {
        0xFF00: "IO_LED_CONTROL",
        0xFF02: "IO_LED_DATA",
        0xFF04: "IO_STATUS_LATCH",
        0xFF06: "IO_KEY_COLUMN_SEL",
        0xFF08: "LCD_CMD_DATA",
        0xFF0E: "IO_TRANSPORT_STATE",
        0xFF0F: "IO_BEAT_DIVIDER",
        0xFF1A: "IO_CLICK_ENABLE",
        0xFF1C: "IO_IDLE_COUNTER",
        0xFF1D: "IO_TIMEOUT_COUNTER",
    }
    symtab = currentProgram.getSymbolTable()
    count = 0
    for offset, name in IO_LABELS.items():
        addr = extmem_space.getAddress(offset)
        try:
            symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            count += 1
        except:
            pass
    print("  Labeled %d I/O registers" % count)


# === MAIN ===
print("=" * 60)
print("Alesis MMT-8 Annotation Script")
print("=" * 60)

print("\nRenaming functions...")
rename_functions()

print("\nAdding plate comments...")
add_plate_comments()

print("\nLabeling IRAM variables...")
label_iram_variables()

print("\nLabeling I/O registers...")
label_xdata_io()

print("\nAnnotation complete!")
