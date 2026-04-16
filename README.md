# PMITool

Linux/arm64 PMI sampler implemented in C with `perf_event_open` and eBPF.

## Scope

- Linux-only collector
- Instruction-period sampling (`1,000,000` retired instructions by default)
- Custom sibling PMU events from CPU core PMU sysfs descriptions
- `perf_event` BPF program for stack/IP enrichment
- Raw sample recording plus function-level report generation

## Build prerequisites

The project code directly depends on `libbpf`, but building vendored `libbpf`
also requires its documented prerequisites:

- `clang`
- `llvm-strip`
- `make`
- `pkg-config`
- `libelf`
- `zlib`

Option 1: use vendored `libbpf`:

```bash
./scripts/fetch_libbpf.sh
make
```

Option 2: use system `libbpf` instead of vendoring it.

Debian/Ubuntu:

```bash
sudo apt-get install -y clang llvm make pkg-config libbpf-dev libelf-dev zlib1g-dev linux-libc-dev
make USE_SYSTEM_LIBBPF=1
```

Fedora/RHEL:

```bash
sudo dnf install -y clang llvm make pkgconf-pkg-config libbpf-devel elfutils-libelf-devel zlib-devel kernel-headers
make USE_SYSTEM_LIBBPF=1
```

openEuler:

```bash
sudo dnf install -y clang llvm make pkgconf-pkg-config libbpf-devel elfutils-libelf-devel zlib-devel kernel-headers
make USE_SYSTEM_LIBBPF=1
```

Arch Linux:

```bash
sudo pacman -S --needed clang llvm make pkgconf libbpf elfutils zlib linux-headers
make USE_SYSTEM_LIBBPF=1
```

Run unit tests:

```bash
make test
# or, if using the system package:
make USE_SYSTEM_LIBBPF=1 test
```

## Commands

Record:

```bash
./build/pmi record --pid 1234 --event cycles --event armv8_pmuv3_0/event=0x08/ --out samples.pmi
```

Launch and record:

```bash
./build/pmi record --cmd 'taskset -c 0 ./bench' --stack full --out samples.pmi
```

Report:

```bash
./build/pmi report --input samples.pmi --limit 20
```

## Raw sample format

`record` writes tab-separated text records:

```text
S <time_ns> <pid> <tid> <cpu> <stream_id> <lost_flags> <ip> <user_stack_id> <kernel_stack_id> <comm> <module> <symbol> <event_blob> <folded_stack>
```

`event_blob` is a comma-separated list:

```text
name@id=value/enabled/running
```

This keeps the output easy to inspect while staying stable enough for the
bundled `report` command.

## Current limits

- Only CPU core PMU alias/raw events are supported
- `record --pid` snapshots and refreshes thread lists periodically, but does not
  attempt to preserve symbol/mmap history after process exit
- Full-stack folded output is best-effort and depends on `/proc/<pid>/maps`
  being readable while recording
