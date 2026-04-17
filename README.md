# PMITool

 Linux/arm64 PMI sampler implemented in C with `perf_event_open`.

## Scope

- Linux-only collector
- Instruction-period sampling (`1,000,000` retired instructions by default)
- Raw sibling PMU events from the CPU core PMU (`-e r0010,r0011`)
- `perf` callchain capture in `--stack full` mode
- Raw sample recording plus function-level report generation

## Build prerequisites

The default build is pure `perf_event_open`; `libbpf` is no longer required.
You only need a C toolchain plus Linux UAPI headers.

- `clang` or `gcc`
- `make`
- kernel headers / `linux-libc-dev`

Debian/Ubuntu:

```bash
sudo apt-get install -y clang make linux-libc-dev
make
```

Fedora/RHEL:

```bash
sudo dnf install -y clang make kernel-headers
make
```

openEuler:

```bash
sudo dnf install -y clang make kernel-headers
make
```

Arch Linux:

```bash
sudo pacman -S --needed clang make linux-headers
make
```

Run unit tests:

```bash
make test
```

## Commands

Record:

```bash
sudo ./build/pmi record -p 1234 -o samples.pmi
```

Launch and record:

```bash
sudo ./build/pmi record -c 'taskset -c 0 ./bench' -s top -o samples.pmi
```

Launch and record with raw PMU events plus a shorter sampling period and full stack:

```bash
sudo ./build/pmi record -c './bench' -n 100000 -e r0010,r0011 -s full -o samples.pmi
```

Report:

```bash
./build/pmi report -i samples.pmi -l 20
```

`report` prints a hotspot table by `top` function and, when `-s full` samples
exist, a second `full stacks` section with symbolized folded stacks.

Help:

```bash
./build/pmi -h
./build/pmi record -h
./build/pmi report -h
```

## Raw sample format

`record` writes tab-separated text records:

```text
S <seq> <insn_total> <insn_expected> <pid> <tid> <top> <events> <stack>
```

- `seq`: sample sequence number starting from 1
- `insn_total`: exact cumulative instructions counter from the leader event
- `insn_expected`: `seq * period_insn`
- `top`: leaf function name; `-` when `-s` is omitted
- `events`: comma-separated custom raw PMU values such as `r0010=123,r0011=456`
- `stack`: `-` when `-s` is omitted or `-s top`; with `-s full` it stores the
  remaining raw callchain IPs after the leaf frame, such as `0xaaa;0xbbb`

The file starts with:

```text
# pmi raw v3
```

`report` reads only this v3 format.

## Current limits

- Only Linux/arm64 is supported
- Only CPU core PMU raw events are supported
- `-e` requires a real CPU PMU; virtual environments without one will fail fast
- `record --pid` snapshots and refreshes thread lists periodically, but does not
  attempt to preserve symbol/mmap history after process exit
- Omitting `-s` disables function and stack output entirely
- `--stack full` uses `PERF_SAMPLE_CALLCHAIN`; user-space unwind quality depends
  on the target binary keeping frame pointers
- Raw stack addresses are recorded during capture and left for offline consumers
  such as `report`
