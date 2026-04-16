PROJECT := pmi
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
BIN := $(BUILD_DIR)/$(PROJECT)
USE_SYSTEM_LIBBPF ?= 0

LIBBPF_DIR := third_party/libbpf/src
LIBBPF_A := $(LIBBPF_DIR)/libbpf.a
LIBBPF_HEADERS := $(LIBBPF_DIR)/root/usr/include
LIBBPF_PKG_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_PKG_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

CC ?= clang
CLANG ?= clang
STRIP ?= llvm-strip

CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=c11
LDFLAGS += -lelf -lz

ifeq ($(USE_SYSTEM_LIBBPF),1)
ifneq ($(filter clean fetch-libbpf,$(MAKECMDGOALS)),)
else
ifeq ($(shell pkg-config --exists libbpf && echo yes),yes)
else
$(error system libbpf not found via pkg-config; install libbpf-devel and pkgconf-pkg-config, or build with vendored libbpf)
endif
endif
endif

ifeq ($(USE_SYSTEM_LIBBPF),1)
CPPFLAGS += -Iinclude $(LIBBPF_PKG_CFLAGS) -D_GNU_SOURCE
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
	-Iinclude $(LIBBPF_PKG_CFLAGS)
LIBBPF_BUILD_DEPS :=
LIBBPF_LINK_INPUT := $(LIBBPF_PKG_LIBS)
else
CPPFLAGS += -Iinclude -I$(LIBBPF_HEADERS) -D_GNU_SOURCE
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
	-Iinclude -I$(LIBBPF_HEADERS) -Ithird_party/libbpf/include/uapi
LIBBPF_BUILD_DEPS := $(LIBBPF_A)
LIBBPF_LINK_INPUT := $(LIBBPF_A)
endif

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

$(BIN): $(LIBBPF_BUILD_DEPS) $(OBJ) $(BPF_BUILD_DIR)/pmi.bpf.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(OBJ) $(LIBBPF_LINK_INPUT) $(LDFLAGS) -o $@

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
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(filter-out $(OBJ_DIR)/main.o,$(OBJ)) $(LIBBPF_LINK_INPUT) $(LDFLAGS) -o $@

test: $(TEST_BIN)
	@set -e; \
	for test_bin in $(TEST_BIN); do \
		echo "running $$test_bin"; \
		$$test_bin; \
	done

clean:
	rm -rf $(BUILD_DIR)
