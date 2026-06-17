# PMITool 开发者测试说明

本文档说明开发 PMITool 时应执行的测试、手工验证方法和常见问题定位流程。

## 1. 测试环境

PMITool 是 Linux-only 工具。完整构建和测试需要 Linux UAPI 头文件：

- `clang` 或 `gcc`
- `make`
- `linux/perf_event.h`
- kernel headers 或 `linux-libc-dev`
- `libdl`

openEuler 示例：

```bash
sudo dnf install -y clang make kernel-headers
make
make test
```

Debian/Ubuntu 示例：

```bash
sudo apt-get install -y clang make linux-libc-dev
make
make test
```

macOS 缺少 Linux perf UAPI 头文件，不能作为完整构建和验证环境。

## 2. 单元测试

执行：

```bash
make test
```

当前测试覆盖：

- `test_event`：CPU PMU sysfs 解析、raw event token 解析、无 CPU PMU 错误路径。
- `test_perf_decode`：`PERF_SAMPLE_READ`、`PERF_SAMPLE_CALLCHAIN`、context marker 过滤。
- `test_record_cpu`：`-C` CPU set 范围解析和 perf open 参数转换。
- `test_output_v3`：raw v3 表头、动态事件列、top/stack 地址输出。
- `test_report_v3`：overview/samples/visual 的 raw v3 解析和展示。
- `test_symbolizer`：ELF 符号解析和地址到符号映射。

新增功能必须优先补单元测试，尤其是 parser、sample decode、raw schema 和 report 解析。

## 3. 基础构建检查

每次提交前至少执行：

```bash
make clean
make
make test
git diff --check
```

如果只在 macOS 上编辑，至少执行：

```bash
git diff --check
```

并在提交说明中明确 Linux 构建未验证的原因。

## 4. record 集成验证

建议准备一个稳定 busy-loop 测试程序，编译时保留 frame pointer：

```bash
gcc -O2 -g -fno-omit-frame-pointer hotloop.c -o hotloop
```

基础录制：

```bash
sudo ./build/pmi record -c './hotloop' -n 100000 -o out.pmi
head -5 out.pmi
```

期望：

- 文件头是 `# pmi raw v3`。
- 第二行是列头。
- 后续样本以 `S` 开头。
- `insn_delta` 非持续 0。

采集叶子地址：

```bash
sudo ./build/pmi record -c './hotloop' -n 100000 -s top -o top.pmi
./build/pmi report -i top.pmi -l 20
```

完整调用链：

```bash
sudo ./build/pmi record -c './hotloop' -n 100000 -s full -o full.pmi
./build/pmi report -i full.pmi -m samples -l 20
```

自定义 PMU 事件：

```bash
sudo ./build/pmi record -c './hotloop' -n 100000 -e r0010,r0011 -o events.pmi
head -5 events.pmi
```

期望：

- 表头包含 `r0010`、`r0011` 独立列。
- 事件列输出 delta，不是 `r0010=...` blob。

CPU 范围采样：

```bash
sudo ./build/pmi record -C 1-4 -n 100000 -o cpu.pmi
sudo ./build/pmi record -C 0,2-4,7 -n 100000 -e r0010,r0011 -s top -o cpu_events.pmi
```

期望：

- raw 输出不出现 CPU 列。
- 多个 CPU 的 sample 合并为一个全局 `seq` 流。
- `pid/tid` 来自 sample 触发时正在 CPU 上运行的任务。

## 5. report 验证

总览模式：

```bash
./build/pmi report -i out.pmi -l 20
```

逐样本模式：

```bash
./build/pmi report -i out.pmi -m samples
```

TID 过滤：

```bash
./build/pmi report -i out.pmi -t 1234
./build/pmi report -i out.pmi -t 1234,5678 -m samples
```

可视化：

```bash
./build/pmi report -i out.pmi -m visual -o visual.html
```

验证重点：

- overview 的样本数和 delta 聚合符合 raw 文件。
- samples 模式保持 raw 顺序。
- C++ 符号展示应尽量 demangle。
- 长函数名和长 stack 不应破坏表格对齐。
- visual HTML 是单文件，无外链依赖。

## 6. debug-perf 定位流程

当 raw 文件只有表头、`insn_delta` 为 0 或事件列异常时，使用：

```bash
sudo ./build/pmi record -C 1-4 -n 100000 --debug-perf -o out.pmi 2> perf.log
```

重点查看：

```bash
grep '\[perf\]\[open\]' perf.log | head
grep '\[perf\]\[enable\]' perf.log | head
grep '\[perf\]\[decode\]' perf.log | head
grep '\[perf\]\[read\]' perf.log | head -50
grep 'sample read id not found' perf.log
```

判断方式：

- 有 open/enable，但没有 decode：sample 没进入 mmap ring。
- 有 count 增长但无 sample：检查 period、权限、内核 perf 配置。
- 有 decode，但 read value 为 0：检查 PMU event 是否有效。
- 出现 `sample read id not found`：说明 sample 中 read id 与 session event id 没匹配上，应优先检查 group read 和 event open 逻辑。

## 7. 权限与环境问题

常见权限限制：

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

如果值过高，可能需要 root、`CAP_PERFMON` 或降低 paranoid：

```bash
sudo sysctl kernel.perf_event_paranoid=1
```

CPU PMU 检查：

```bash
ls /sys/bus/event_source/devices
cat /sys/bus/event_source/devices/*/type
find /sys/bus/event_source/devices -path '*/format/event' -print
```

虚拟机里可能没有真实 CPU PMU，此时 `-e rXXXX` 会 fail fast。

## 8. 提交前验收清单

- `make test` 在 Linux 通过。
- raw v3 schema 没有无意变化。
- `record` 热路径没有新增符号化或重型 I/O。
- 新 CLI 参数有帮助文案和 README 示例。
- 新解析逻辑有非法输入测试。
- `report` 三种模式不回归。
- `git diff --check` 通过。
