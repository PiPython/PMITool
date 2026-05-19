# PMITool

Linux/arm64 PMI sampler implemented in C with `perf_event_open` and eBPF.

## Scope

- Linux-only collector
- Instruction-period sampling (`1,000,000` retired instructions by default)
- Raw sibling PMU events from the CPU core PMU (`-e r0010,r0011`)
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
sudo ./build/pmi record -p 1234 -o samples.pmi
```

Launch and record:

```bash
sudo ./build/pmi record -c 'taskset -c 0 ./bench' -s full -o samples.pmi
```

Launch and record with raw PMU events plus a shorter sampling period:

```bash
sudo ./build/pmi record -c './bench' -n 100000 -e r0010,r0011 -o samples.pmi
```

Report:

```bash
./build/pmi report -i samples.pmi -l 20
```

Help:

```bash
./build/pmi -h
./build/pmi record -h
./build/pmi report -h
```

## Raw sample format

`record` writes tab-separated text records:

```text
S <seq> <insn_total> <insn_expected> <pid> <tid> <ip> <symbol> <events> <stack>
```

- `seq`: sample sequence number starting from 1
- `insn_total`: exact cumulative instructions counter from the leader event
- `insn_expected`: `seq * period_insn`
- `events`: comma-separated custom raw PMU values such as `r0010=123,r0011=456`
- `stack`: `-` in `top` mode, or raw user-stack IPs such as `0xaaa;0xbbb;0xccc`

The file starts with:

```text
# pmi raw v2
```

`report` reads only this v2 format.

## Current limits

- Only Linux/arm64 is supported
- Only CPU core PMU raw events are supported
- `-e` requires a real CPU PMU; virtual environments without one will fail fast
- `record --pid` snapshots and refreshes thread lists periodically, but does not
  attempt to preserve symbol/mmap history after process exit
- `--stack full` records raw stack addresses during capture and leaves full-stack
  symbolization to offline consumers such as `report`
