CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  :=

BUILD_DIR := build
BIN       := $(BUILD_DIR)/test_helper

.PHONY: all clean
all: $(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BIN): test_helper.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD_DIR)
