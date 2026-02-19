CC = gcc
CFLAGS = -Wall -Wextra -O2 -g $(shell sdl2-config --cflags)
LDFLAGS = $(shell sdl2-config --libs) -lSDL2_ttf -lm
SRCS = main.c core.c opcodes.c disasm.c mmt8_hw.c mmt8_gui.c
OBJS = $(SRCS:.c=.o)
TARGET = mmt8sim

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
