PROJECT := pmi
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN := $(BUILD_DIR)/$(PROJECT)

CC ?= clang
CC_IS_GCC := $(shell printf '' | $(CC) -dM -E - 2>/dev/null | awk '/__GNUC__/ { gcc = 1 } /__clang__/ { clang = 1 } END { print (gcc && !clang) ? 1 : 0 }')

CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=c11
CFLAGS += -pthread
ifeq ($(CC_IS_GCC),1)
CFLAGS += -Wno-format-truncation
endif
CPPFLAGS += -Iinclude -D_GNU_SOURCE
LDFLAGS += -pthread
LDLIBS += -ldl

SRC := \
	src/main.c \
	src/record.c \
	src/report.c \
	src/event.c \
	src/procfs.c \
	src/perf_session.c \
	src/output.c \
	src/symbolizer.c

OBJ := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRC))

TEST_SRC := \
	tests/test_event.c \
	tests/test_perf_decode.c \
	tests/test_symbolizer.c \
	tests/test_output_v2.c \
	tests/test_report_v2.c

TEST_BIN := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRC))

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: src/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

$(OBJ_DIR):
	mkdir -p $@

$(BUILD_DIR)/test_%: tests/test_%.c $(filter-out $(OBJ_DIR)/main.o,$(OBJ)) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(filter-out $(OBJ_DIR)/main.o,$(OBJ)) $(LDFLAGS) $(LDLIBS) -o $@

test: $(TEST_BIN)
	@set -e; \
	for test_bin in $(TEST_BIN); do \
		echo "running $$test_bin"; \
		$$test_bin; \
	done

clean:
	rm -rf $(BUILD_DIR)
