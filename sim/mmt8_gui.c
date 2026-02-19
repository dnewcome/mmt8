#include <stdio.h>
#include <string.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include "emu8051.h"
#include "mmt8_hw.h"
#include "mmt8_gui.h"

/* ---- Window dimensions ---- */
#define WIN_W 820
#define WIN_H 500

/* ---- Colors ---- */
#define COL_BG_R       45
#define COL_BG_G       45
#define COL_BG_B       50
#define COL_LCD_BG_R   0x33
#define COL_LCD_BG_G   0x22
#define COL_LCD_BG_B   0x00
#define COL_LCD_FG_R   0xFF
#define COL_LCD_FG_G   0xAA
#define COL_LCD_FG_B   0x00
#define COL_BTN_R      70
#define COL_BTN_G      70
#define COL_BTN_B      75
#define COL_BTN_PR_R   50
#define COL_BTN_PR_G   50
#define COL_BTN_PR_B   55
#define COL_TXT_R      220
#define COL_TXT_G      220
#define COL_TXT_B      220
#define COL_LED_ON_R   0
#define COL_LED_ON_G   220
#define COL_LED_ON_B   0
#define COL_LED_OFF_R  30
#define COL_LED_OFF_G  40
#define COL_LED_OFF_B  30
#define COL_LED_RED_R  220
#define COL_LED_RED_G  0
#define COL_LED_RED_B  0
#define COL_LED_RED_OFF_R  40
#define COL_LED_RED_OFF_G  20
#define COL_LED_RED_OFF_B  20

/* ---- Button definition ---- */
typedef struct {
    SDL_Rect rect;
    const char *label;
    int col;          /* keyboard matrix column */
    int row;          /* keyboard matrix row */
    int pressed;
    int has_led;      /* 0=none, 1=green LED, 2=red LED */
    int led_bit;      /* which bit in led_data or led_control */
} button_t;

/* ---- LED position relative to button ---- */
#define LED_RADIUS 4

/* ---- Forward declarations ---- */
static void init_buttons(void);
static button_t *find_button(int x, int y);

/* ---- State ---- */
static SDL_Window   *window;
static SDL_Renderer *renderer;
static TTF_Font     *font_lcd;
static TTF_Font     *font_btn;
static TTF_Font     *font_small;

/* Buttons array — filled in init_buttons() */
#define MAX_BUTTONS 50
static button_t buttons[MAX_BUTTONS];
static int num_buttons;

/* ---- Button layout helpers ---- */

static void add_button(int x, int y, int w, int h,
                       const char *label, int col, int row,
                       int has_led, int led_bit)
{
    if (num_buttons >= MAX_BUTTONS) return;
    button_t *b = &buttons[num_buttons++];
    b->rect = (SDL_Rect){x, y, w, h};
    b->label = label;
    b->col = col;
    b->row = row;
    b->pressed = 0;
    b->has_led = has_led;
    b->led_bit = led_bit;
}

/*
 * Keyboard matrix mapping (initial best-guess from firmware analysis).
 * Column select via 0xFF06: bit 0..5 active-low.
 * Row read via P1: bits 0..7.
 *
 * These assignments will need refinement by testing with the running firmware.
 * The mapping is organized by functional groups on the front panel.
 */
static void init_buttons(void)
{
    int bw = 52, bh = 28;    /* standard button size */
    int tw = 42, th = 36;    /* track button size */
    int nw = 34, nh = 28;    /* numpad button size */
    int gap = 6;

    num_buttons = 0;

    /* --- Row 1: Mode buttons (y=20) --- */
    int y = 20;
    int x = 260;
    add_button(x, y, bw, bh, "PART",  0, 0, 1, 0);  x += bw + gap;
    add_button(x, y, bw, bh, "EDIT",  0, 1, 1, 1);   x += bw + gap;
    add_button(x, y, bw, bh, "SONG",  0, 2, 1, 2);   x += bw + gap;
    add_button(x, y, bw, bh, "NAME",  0, 3, 0, 0);

    /* --- Row 2: Function buttons (y=60) --- */
    y = 60;
    x = 260;
    add_button(x, y, bw, bh, "CLICK",  0, 4, 0, 0);  x += bw + gap;
    add_button(x, y, bw, bh, "COPY",   0, 5, 0, 0);   x += bw + gap;
    add_button(x, y, bw, bh, "ERASE",  0, 6, 0, 0);   x += bw + gap;
    add_button(x, y, bw, bh, "TEMPO",  0, 7, 0, 0);

    /* --- Row 3: More functions (y=100) --- */
    y = 100;
    x = 20;
    add_button(x, y, bw, bh, "LOOP",     1, 0, 1, 3);  x += bw + gap;
    add_button(x, y, bw+12, bh, "ECHO",   1, 1, 1, 4);  x += bw + 12 + gap;
    add_button(x, y, bw, bh, "LENGTH",   1, 2, 0, 0);   x += bw + gap;
    add_button(x, y, bw, bh, "MERGE",    1, 3, 0, 0);

    /* --- Row 4: Even more functions (y=140) --- */
    y = 140;
    x = 20;
    add_button(x, y, bw, bh, "QUANT",     1, 4, 0, 0);  x += bw + gap;
    add_button(x, y, bw+4, bh, "TRANS",    1, 5, 0, 0);  x += bw + 4 + gap;
    add_button(x, y, bw+4, bh, "FILTER",   1, 6, 0, 0);  x += bw + 4 + gap;
    add_button(x, y, bw+4, bh, "MIDI CH",  1, 7, 0, 0);  x += bw + 4 + gap;
    add_button(x, y, bw, bh, "CLOCK",     2, 0, 0, 0);  x += bw + gap;
    add_button(x, y, bw, bh, "TAPE",      2, 1, 0, 0);

    /* --- Track buttons with LEDs (y=200) --- */
    y = 200;
    x = 20;
    for (int i = 0; i < 8; i++) {
        char *labels[] = {"1","2","3","4","5","6","7","8"};
        add_button(x, y, tw, th, labels[i], 2+i/4, 2+(i%4), 1, i);
        x += tw + gap;
    }

    /* --- Numeric keypad (y=280) --- */
    y = 280;
    x = 20;
    for (int i = 0; i < 10; i++) {
        char *labels[] = {"0","1","2","3","4","5","6","7","8","9"};
        /* Map digits across columns 3-5 */
        int dcol = 3 + (i / 4);
        int drow = i % 4;
        add_button(x, y, nw, nh, labels[i], dcol, drow, 0, 0);
        x += nw + gap;
    }

    /* --- +/- buttons --- */
    x += gap;
    add_button(x, y, nw, nh, "+", 4, 4, 0, 0);  x += nw + gap;
    add_button(x, y, nw, nh, "-", 4, 5, 0, 0);

    /* --- Transport buttons (y=330) --- */
    y = 330;
    x = 20;
    add_button(x, y, bw, bh, "<<",   5, 0, 0, 0);  x += bw + gap;
    add_button(x, y, bw, bh, ">>",   5, 1, 0, 0);  x += bw + gap + 20;
    add_button(x, y, bw, bh, "PLAY", 5, 2, 1, 5);   x += bw + gap;
    add_button(x, y, bw+8, bh, "STOP",  5, 3, 0, 0);  x += bw + 8 + gap;
    add_button(x, y, bw, bh, "REC",  5, 4, 2, 6);
}

/* Find which button contains point (x,y) */
static button_t *find_button(int x, int y)
{
    for (int i = 0; i < num_buttons; i++) {
        SDL_Rect *r = &buttons[i].rect;
        if (x >= r->x && x < r->x + r->w &&
            y >= r->y && y < r->y + r->h)
            return &buttons[i];
    }
    return NULL;
}

/* ---- Rendering ---- */

static void render_lcd(void)
{
    lcd_state_t *lcd = mmt8_get_lcd();
    SDL_Rect border = {18, 18, 224, 64};
    SDL_Rect inner  = {20, 20, 220, 60};

    /* Border */
    SDL_SetRenderDrawColor(renderer, 100, 100, 100, 255);
    SDL_RenderDrawRect(renderer, &border);

    /* Background */
    SDL_SetRenderDrawColor(renderer, COL_LCD_BG_R, COL_LCD_BG_G, COL_LCD_BG_B, 255);
    SDL_RenderFillRect(renderer, &inner);

    if (!font_lcd) return;

    SDL_Color fg = {COL_LCD_FG_R, COL_LCD_FG_G, COL_LCD_FG_B, 255};

    for (int line = 0; line < 2; line++) {
        char text[17];
        for (int i = 0; i < 16; i++) {
            uint8_t ch = lcd->ddram[line][i];
            if (ch < 0x20 || ch > 0x7E)
                text[i] = ' ';
            else
                text[i] = ch;
        }
        text[16] = '\0';

        SDL_Surface *surf = TTF_RenderText_Blended(font_lcd, text, fg);
        if (surf) {
            SDL_Texture *tex = SDL_CreateTextureFromSurface(renderer, surf);
            SDL_Rect dst = {24, 24 + line * 28, surf->w, surf->h};
            SDL_RenderCopy(renderer, tex, NULL, &dst);
            SDL_DestroyTexture(tex);
            SDL_FreeSurface(surf);
        }
    }
}

static void render_buttons(void)
{
    uint8_t led_d = mmt8_get_led_data();
    uint8_t led_c = mmt8_get_led_control();
    (void)led_c;

    SDL_Color txt_color = {COL_TXT_R, COL_TXT_G, COL_TXT_B, 255};

    for (int i = 0; i < num_buttons; i++) {
        button_t *b = &buttons[i];

        /* Button fill */
        if (b->pressed)
            SDL_SetRenderDrawColor(renderer, COL_BTN_PR_R, COL_BTN_PR_G, COL_BTN_PR_B, 255);
        else
            SDL_SetRenderDrawColor(renderer, COL_BTN_R, COL_BTN_G, COL_BTN_B, 255);
        SDL_RenderFillRect(renderer, &b->rect);

        /* Button border */
        SDL_SetRenderDrawColor(renderer, 100, 100, 100, 255);
        SDL_RenderDrawRect(renderer, &b->rect);

        /* Label */
        if (font_btn && b->label) {
            TTF_Font *f = (strlen(b->label) > 4) ? font_small : font_btn;
            SDL_Surface *surf = TTF_RenderText_Blended(f, b->label, txt_color);
            if (surf) {
                SDL_Texture *tex = SDL_CreateTextureFromSurface(renderer, surf);
                int tx = b->rect.x + (b->rect.w - surf->w) / 2;
                int ty = b->rect.y + (b->rect.h - surf->h) / 2;
                SDL_Rect dst = {tx, ty, surf->w, surf->h};
                SDL_RenderCopy(renderer, tex, NULL, &dst);
                SDL_DestroyTexture(tex);
                SDL_FreeSurface(surf);
            }
        }

        /* LED indicator */
        if (b->has_led) {
            int cx = b->rect.x + b->rect.w / 2;
            int cy = b->rect.y - LED_RADIUS - 3;
            int on = (led_d >> b->led_bit) & 1;

            if (b->has_led == 2) {
                /* Red LED (REC) */
                if (on)
                    SDL_SetRenderDrawColor(renderer, COL_LED_RED_R, COL_LED_RED_G, COL_LED_RED_B, 255);
                else
                    SDL_SetRenderDrawColor(renderer, COL_LED_RED_OFF_R, COL_LED_RED_OFF_G, COL_LED_RED_OFF_B, 255);
            } else {
                /* Green LED */
                if (on)
                    SDL_SetRenderDrawColor(renderer, COL_LED_ON_R, COL_LED_ON_G, COL_LED_ON_B, 255);
                else
                    SDL_SetRenderDrawColor(renderer, COL_LED_OFF_R, COL_LED_OFF_G, COL_LED_OFF_B, 255);
            }

            /* Draw filled circle (simple square approximation) */
            SDL_Rect led_rect = {cx - LED_RADIUS, cy - LED_RADIUS,
                                 LED_RADIUS * 2, LED_RADIUS * 2};
            SDL_RenderFillRect(renderer, &led_rect);
        }
    }
}

/* ---- Public API ---- */

int gui_init(void)
{
    if (SDL_Init(SDL_INIT_VIDEO) < 0) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return -1;
    }

    if (TTF_Init() < 0) {
        fprintf(stderr, "TTF_Init failed: %s\n", TTF_GetError());
        return -1;
    }

    window = SDL_CreateWindow("MMT-8 Simulator",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        WIN_W, WIN_H, SDL_WINDOW_SHOWN);
    if (!window) {
        fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        return -1;
    }

    renderer = SDL_CreateRenderer(window, -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        fprintf(stderr, "SDL_CreateRenderer failed: %s\n", SDL_GetError());
        return -1;
    }

    /* Try to load a monospace font for the LCD */
    const char *font_paths[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        NULL
    };

    const char *font_path = NULL;
    for (int i = 0; font_paths[i]; i++) {
        FILE *f = fopen(font_paths[i], "r");
        if (f) {
            fclose(f);
            font_path = font_paths[i];
            break;
        }
    }

    if (font_path) {
        font_lcd   = TTF_OpenFont(font_path, 22);
        font_btn   = TTF_OpenFont(font_path, 12);
        font_small = TTF_OpenFont(font_path, 10);
    } else {
        fprintf(stderr, "Warning: no monospace font found, text will not render\n");
    }

    init_buttons();
    return 0;
}

void gui_handle_event(SDL_Event *ev)
{
    if (ev->type == SDL_MOUSEBUTTONDOWN) {
        button_t *b = find_button(ev->button.x, ev->button.y);
        if (b) {
            b->pressed = 1;
            mmt8_key_press(b->col, b->row);
        }
    } else if (ev->type == SDL_MOUSEBUTTONUP) {
        /* Release all pressed buttons */
        for (int i = 0; i < num_buttons; i++) {
            if (buttons[i].pressed) {
                buttons[i].pressed = 0;
                mmt8_key_release(buttons[i].col, buttons[i].row);
            }
        }
    }
}

void gui_render(struct em8051 *cpu)
{
    (void)cpu;

    /* Clear background */
    SDL_SetRenderDrawColor(renderer, COL_BG_R, COL_BG_G, COL_BG_B, 255);
    SDL_RenderClear(renderer);

    render_lcd();
    render_buttons();

    SDL_RenderPresent(renderer);
}

void gui_shutdown(void)
{
    if (font_lcd)   TTF_CloseFont(font_lcd);
    if (font_btn)   TTF_CloseFont(font_btn);
    if (font_small) TTF_CloseFont(font_small);
    if (renderer)   SDL_DestroyRenderer(renderer);
    if (window)     SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();
}
