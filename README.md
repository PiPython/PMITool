# PMITool

Linux/arm64 PMI sampler implemented in C with `perf_event_open`.

## Scope

- Linux-only collector
- Instruction-period sampling (`1,000,000` retired instructions by default)
- Raw sibling PMU events from the CPU core PMU (`-e r0010,r0011`)
- `perf` callchain capture in `--stack full` mode
- Raw sample recording plus function-level report generation

## Build prerequisites

The build is pure `perf_event_open`.
You only need a C toolchain, Linux UAPI headers, and `libdl`.

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

Per-sample report:

```bash
./build/pmi report -i samples.pmi -m samples
```

Filter report output by one or more tids:

```bash
./build/pmi report -i samples.pmi -t 1234,5678
```

`report` defaults to an overview table by `top` function and, when `-s full`
samples exist, a second `full stacks` section with symbolized folded stacks.
`-m samples` instead prints every sample in file order. Any `-e` events are
expanded into one column per event name in both raw output and report output.
When symbols are mangled C++ names, `report` will demangle them for display.

Help:

```bash
./build/pmi -h
./build/pmi record -h
./build/pmi report -h
```

## Raw sample format

`record` writes tab-separated text records:

Without `-e`, rows look like:

```text
S <seq> <insn_delta> <pid> <tid> <top> <stack>
```

With `-e r0010,r0011`, rows look like:

```text
S <seq> <insn_delta> <pid> <tid> <r0010> <r0011> <top> <stack>
```

- `seq`: sample sequence number starting from 1
- `insn_delta`: instructions retired since the previous sample of the same `tid`
- `top`: leaf function name; `-` when `-s` is omitted
- each `-e` event becomes its own delta column named after the raw event, such
  as `r0010` or `r0011`
- `stack`: `-` when `-s` is omitted or `-s top`; with `-s full` it stores the
  remaining raw callchain IPs after the leaf frame, such as `0xaaa;0xbbb`

For each `tid`, the first sample writes the current counter values as its delta.

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
