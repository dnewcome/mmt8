#include <string.h>
#include <stdio.h>
#include "emu8051.h"
#include "mmt8_hw.h"

/* ---- Hardware latch state ---- */
static uint8_t led_control;      /* 0xFF00 */
static uint8_t led_data;         /* 0xFF02 */
static uint8_t status_latch;     /* 0xFF04 */
static uint8_t key_column_sel;   /* 0xFF06 */
static uint8_t transport_state;  /* 0xFF0E */
static uint8_t beat_divider;     /* 0xFF0F */
static uint8_t click_enable;     /* 0xFF1A */

/* ---- LCD ---- */
static lcd_state_t lcd;

/* ---- Keyboard matrix (6 columns x 8 rows) ---- */
/* Each element is a bitmask of pressed rows for that column */
static uint8_t key_matrix[6];

/* ---- LCD helpers ---- */

static void lcd_write_command(uint8_t cmd)
{
    if (cmd == 0x01) {
        /* Clear display */
        memset(lcd.ddram, ' ', sizeof(lcd.ddram));
        lcd.cursor_addr = 0;
    } else if (cmd == 0x02) {
        /* Return home */
        lcd.cursor_addr = 0;
    } else if ((cmd & 0xFC) == 0x04) {
        /* Entry mode set */
        lcd.entry_increment = (cmd & 0x02) ? 1 : 0;
    } else if ((cmd & 0xF8) == 0x08) {
        /* Display on/off control */
        lcd.display_on = (cmd & 0x04) ? 1 : 0;
        lcd.cursor_on  = (cmd & 0x02) ? 1 : 0;
        lcd.blink_on   = (cmd & 0x01) ? 1 : 0;
    } else if ((cmd & 0xE0) == 0x20) {
        /* Function set (0x38 = 8-bit, 2 lines) — just accept it */
    } else if (cmd & 0x80) {
        /* Set DDRAM address */
        lcd.cursor_addr = cmd & 0x7F;
    }
    /* Other commands (shift, CGRAM) ignored for now */
}

static void lcd_write_data(uint8_t data)
{
    int line, pos;

    if (lcd.cursor_addr >= 0x40) {
        line = 1;
        pos = lcd.cursor_addr - 0x40;
    } else {
        line = 0;
        pos = lcd.cursor_addr;
    }

    if (pos >= 0 && pos < 40) {
        lcd.ddram[line][pos] = data;
    }

    if (lcd.entry_increment)
        lcd.cursor_addr++;
    else
        lcd.cursor_addr--;

    lcd.cursor_addr &= 0x7F;
}

/* ---- Public API ---- */

void mmt8_hw_init(void)
{
    led_control = 0;
    led_data = 0;
    status_latch = 0;
    key_column_sel = 0xFF;
    transport_state = 0;
    beat_divider = 0;
    click_enable = 0;

    memset(&lcd, 0, sizeof(lcd));
    memset(lcd.ddram, ' ', sizeof(lcd.ddram));
    lcd.entry_increment = 1;

    memset(key_matrix, 0, sizeof(key_matrix));
}

void mmt8_hw_install(struct em8051 *cpu)
{
    cpu->xread = mmt8_xdata_read;
    cpu->xwrite = mmt8_xdata_write;
    cpu->sfrread[REG_P1] = mmt8_p1_read;
}

void mmt8_xdata_write(struct em8051 *cpu, uint16_t addr, uint8_t val)
{
    if (addr < 0xFF00) {
        cpu->mExtData[addr] = val;
        return;
    }
    switch (addr) {
        case 0xFF00: led_control = val; break;
        case 0xFF02: led_data = val; break;
        case 0xFF04: status_latch = val; break;
        case 0xFF06: key_column_sel = val; break;
        case 0xFF08: lcd_write_command(val); break;
        case 0xFF09: lcd_write_data(val); break;
        case 0xFF0E: transport_state = val; break;
        case 0xFF0F: beat_divider = val; break;
        case 0xFF1A: click_enable = val; break;
        default:     cpu->mExtData[addr] = val; break;
    }
}

uint8_t mmt8_xdata_read(struct em8051 *cpu, uint16_t addr)
{
    if (addr < 0xFF00)
        return cpu->mExtData[addr];
    switch (addr) {
        case 0xFF04: return status_latch;
        case 0xFF0E: return transport_state;
        case 0xFF0F: return beat_divider;
        case 0xFF1A: return click_enable;
        default:     return cpu->mExtData[addr];
    }
}

uint8_t mmt8_p1_read(struct em8051 *cpu, uint8_t reg)
{
    (void)cpu;
    (void)reg;
    uint8_t result = 0xFF;
    for (int col = 0; col < 6; col++) {
        if (!(key_column_sel & (1 << col))) {
            result &= ~key_matrix[col];
        }
    }
    return result;
}

lcd_state_t *mmt8_get_lcd(void) { return &lcd; }
uint8_t mmt8_get_led_control(void) { return led_control; }
uint8_t mmt8_get_led_data(void)    { return led_data; }

void mmt8_key_press(int col, int row)
{
    if (col >= 0 && col < 6 && row >= 0 && row < 8)
        key_matrix[col] |= (1 << row);
}

void mmt8_key_release(int col, int row)
{
    if (col >= 0 && col < 6 && row >= 0 && row < 8)
        key_matrix[col] &= ~(1 << row);
}
