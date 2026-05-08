CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  := -lm

BUILD_DIR := build
BIN       := $(BUILD_DIR)/bench_open

.PHONY: all clean
all: $(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BIN): bench_open.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD_DIR)
