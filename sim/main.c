#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SDL2/SDL.h>
#include "emu8051.h"
#include "mmt8_hw.h"
#include "mmt8_gui.h"

#define ROM_SIZE 32768
#define XDATA_SIZE 65536

static struct em8051 cpu;
static int running = 1;

static int load_firmware(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open firmware: %s\n", path);
        return -1;
    }
    size_t n = fread(cpu.mCodeMem, 1, ROM_SIZE, f);
    fclose(f);
    if (n != ROM_SIZE) {
        fprintf(stderr, "Warning: firmware is %zu bytes (expected %d)\n", n, ROM_SIZE);
    }
    printf("Loaded %zu bytes of firmware from %s\n", n, path);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *rom_path = "../firmware/alesis_mmt8_v111.bin";
    if (argc > 1)
        rom_path = argv[1];

    /* Initialize GUI */
    if (gui_init() < 0) {
        fprintf(stderr, "GUI init failed\n");
        return 1;
    }

    /* Initialize hardware emulation */
    mmt8_hw_init();

    /* Initialize emu8051 */
    memset(&cpu, 0, sizeof(cpu));
    cpu.mCodeMem = malloc(ROM_SIZE);
    cpu.mCodeMemMaxIdx = ROM_SIZE - 1;
    cpu.mExtData = malloc(XDATA_SIZE);
    cpu.mExtDataMaxIdx = XDATA_SIZE - 1;
    cpu.mUpperData = malloc(128);

    if (!cpu.mCodeMem || !cpu.mExtData || !cpu.mUpperData) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    memset(cpu.mExtData, 0, XDATA_SIZE);
    memset(cpu.mUpperData, 0, 128);

    reset(&cpu, 1);

    /* Install hardware callbacks */
    mmt8_hw_install(&cpu);

    /* Load firmware */
    if (load_firmware(rom_path) < 0)
        return 1;

    printf("MMT-8 Simulator starting...\n");
    printf("CPU reset, PC=0x%04X\n", cpu.mPC);

    uint64_t last_time = SDL_GetPerformanceCounter();
    uint64_t freq = SDL_GetPerformanceFrequency();
    uint64_t total_cycles = 0;
    int lcd_dumped = 0;

    while (running) {
        uint64_t now = SDL_GetPerformanceCounter();
        uint64_t elapsed_ticks = now - last_time;
        last_time = now;

        /* Convert to microseconds, then to machine cycles (1 cycle/us at 12MHz/12) */
        int cycles = (int)((elapsed_ticks * 1000000ULL) / freq);
        if (cycles > 50000) cycles = 50000;  /* Cap to avoid spiral */

        for (int i = 0; i < cycles; i++) {
            tick(&cpu);
            total_cycles++;
        }

        /* Debug: dump LCD contents once after enough cycles */
        if (!lcd_dumped && total_cycles > 500000) {
            lcd_state_t *lcd = mmt8_get_lcd();
            char line0[17], line1[17];
            for (int i = 0; i < 16; i++) {
                line0[i] = (lcd->ddram[0][i] >= 0x20 && lcd->ddram[0][i] <= 0x7E)
                    ? lcd->ddram[0][i] : ' ';
                line1[i] = (lcd->ddram[1][i] >= 0x20 && lcd->ddram[1][i] <= 0x7E)
                    ? lcd->ddram[1][i] : ' ';
            }
            line0[16] = line1[16] = '\0';
            printf("LCD after %llu cycles:\n", (unsigned long long)total_cycles);
            printf("  Line 0: [%s]\n", line0);
            printf("  Line 1: [%s]\n", line1);
            printf("  PC=0x%04X\n", cpu.mPC);
            lcd_dumped = 1;
        }

        /* Process SDL events */
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_QUIT) {
                running = 0;
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_ESCAPE) {
                running = 0;
            } else {
                gui_handle_event(&ev);
            }
        }

        /* Render */
        gui_render(&cpu);

        /* Small delay to avoid burning CPU when vsync isn't working */
        SDL_Delay(1);
    }

    /* Cleanup */
    gui_shutdown();
    free(cpu.mCodeMem);
    free(cpu.mExtData);
    free(cpu.mUpperData);

    return 0;
}
