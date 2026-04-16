PROJECT := pmi
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
BIN := $(BUILD_DIR)/$(PROJECT)

LIBBPF_DIR := third_party/libbpf/src
LIBBPF_A := $(LIBBPF_DIR)/libbpf.a
LIBBPF_HEADERS := $(LIBBPF_DIR)/root/usr/include

CC ?= clang
CLANG ?= clang
STRIP ?= llvm-strip

CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=c11
CPPFLAGS += -Iinclude -I$(LIBBPF_HEADERS) -D_GNU_SOURCE
LDFLAGS += -lelf -lz

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
	-Iinclude -I$(LIBBPF_HEADERS) -Ithird_party/libbpf/include/uapi

SRC := \
	src/main.c \
	src/record.c \
	src/report.c \
	src/event.c \
	src/procfs.c \
	src/perf_session.c \
	src/bpf_loader.c \
	src/joiner.c \
	src/output.c \
	src/symbolizer.c

OBJ := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRC))

TEST_SRC := \
	tests/test_event.c \
	tests/test_perf_decode.c \
	tests/test_joiner.c \
	tests/test_symbolizer.c

TEST_BIN := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRC))

.PHONY: all clean test fetch-libbpf

all: $(BIN)

fetch-libbpf:
	./scripts/fetch_libbpf.sh

$(BIN): $(LIBBPF_A) $(OBJ) $(BPF_BUILD_DIR)/pmi.bpf.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OBJ) $(LIBBPF_A) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: src/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BPF_BUILD_DIR)/pmi.bpf.o: bpf/pmi.bpf.c include/pmi/shared.h | $(BPF_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(STRIP) -g $@

$(LIBBPF_A):
	@if [ ! -f "$(LIBBPF_A)" ]; then \
		if [ ! -d "$(LIBBPF_DIR)" ]; then \
			echo "libbpf not found. Run ./scripts/fetch_libbpf.sh first."; \
			exit 1; \
		fi; \
	fi
	$(MAKE) -C $(LIBBPF_DIR) BUILD_STATIC_ONLY=1

$(BUILD_DIR):
	mkdir -p $@

$(OBJ_DIR):
	mkdir -p $@

$(BPF_BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/test_%: tests/test_%.c $(filter-out $(OBJ_DIR)/main.o,$(OBJ)) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(filter-out $(OBJ_DIR)/main.o,$(OBJ)) $(LIBBPF_A) $(LDFLAGS) -o $@

test: $(TEST_BIN)
	@set -e; \
	for test_bin in $(TEST_BIN); do \
		echo "running $$test_bin"; \
		$$test_bin; \
	done

clean:
	rm -rf $(BUILD_DIR)
