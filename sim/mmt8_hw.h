#ifndef MMT8_HW_H
#define MMT8_HW_H

#include "emu8051.h"

/* HD44780 LCD state */
typedef struct {
    uint8_t ddram[2][40];   /* 2 lines x 40 chars */
    uint8_t cursor_addr;    /* current DDRAM address */
    int     display_on;
    int     cursor_on;
    int     blink_on;
    int     entry_increment; /* 1 = increment, 0 = decrement */
} lcd_state_t;

/* Initialize hardware emulation state */
void mmt8_hw_init(void);

/* Install callbacks on an em8051 instance */
void mmt8_hw_install(struct em8051 *cpu);

/* XDATA read/write callbacks */
uint8_t mmt8_xdata_read(struct em8051 *cpu, uint16_t addr);
void    mmt8_xdata_write(struct em8051 *cpu, uint16_t addr, uint8_t val);

/* P1 SFR read callback (keyboard row input) */
uint8_t mmt8_p1_read(struct em8051 *cpu, uint8_t reg);

/* Access hardware state from GUI */
lcd_state_t *mmt8_get_lcd(void);
uint8_t      mmt8_get_led_control(void);
uint8_t      mmt8_get_led_data(void);

/* Keyboard matrix: set/clear a key press (col 0-5, row 0-7) */
void mmt8_key_press(int col, int row);
void mmt8_key_release(int col, int row);

#endif /* MMT8_HW_H */
