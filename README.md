# PMITool

基于 `perf_event_open` 的 Linux/arm64 PMI 采样工具，使用 C 实现。

## 功能范围

- 仅支持 Linux
- 按指令周期采样，默认每退休 `1,000,000` 条指令采一次
- 支持来自 CPU core PMU 的原始 sibling 事件（`-e r0010,r0011`）
- 在 `--stack full` 模式下使用 `perf` 采集调用链
- 支持原始样本落盘与函数级报表生成
- `record` 默认使用低开销异步 writer，尽量减少对业务线程的阻塞

## 构建依赖

当前构建是纯 `perf_event_open` 方案。
只需要 C 工具链、Linux UAPI 头文件以及 `libdl`。

- `clang` or `gcc`
- `make`
- kernel headers / `linux-libc-dev`

Debian/Ubuntu：

```bash
sudo apt-get install -y clang make linux-libc-dev
make
```

Fedora/RHEL：

```bash
sudo dnf install -y clang make kernel-headers
make
```

openEuler：

```bash
sudo dnf install -y clang make kernel-headers
make
```

Arch Linux：

```bash
sudo pacman -S --needed clang make linux-headers
make
```

运行单元测试：

```bash
make test
```

## 常用命令

录制：

```bash
sudo ./build/pmi record -p 1234 -o samples.pmi
```

启动新程序并录制：

```bash
sudo ./build/pmi record -c 'taskset -c 0 ./bench' -s top -o samples.pmi
```

启动新程序并录制，同时指定原始 PMU 事件、较短采样周期和完整调用栈：

```bash
sudo ./build/pmi record -c './bench' -n 100000 -e r0010,r0011 -s full -o samples.pmi
```

使用严格写出模式，尽量不丢 userspace 样本：

```bash
sudo ./build/pmi record -c './bench' --write-mode strict -o samples.pmi
```

生成总览报表：

```bash
./build/pmi report -i samples.pmi -l 20
```

逐样本报表：

```bash
./build/pmi report -i samples.pmi -m samples
```

生成时序热点可视化 HTML：

```bash
./build/pmi report -i samples.pmi -m visual -o visual.html
```

按一个或多个 tid 过滤报表：

```bash
./build/pmi report -i samples.pmi -t 1234,5678
```

`report` 默认输出按 `top` 函数聚合的总览表；如果存在 `-s full`
采到的样本，还会额外输出一个 `full stacks` 分区，展示已经符号化的 folded stack。
`-m samples` 会按文件顺序逐条输出每个 sample。若录制时指定了 `-e`，
这些事件会在 raw 输出和 report 输出中展开为独立列。
若符号名是 C++ mangled 名称，`report` 会在展示阶段自动做 demangle。
`report` 输出是对齐的人类可读表格；过长的 `top` 和 `stack` 字段会截断为 `...`，
以保证终端可读性。
`-m visual` 会生成单文件离线 HTML，先展示全量概览，再通过 brush 选区进入细节散点图和当前区间趋势图；
横轴始终是 sample 序号 `seq`，这里的“时间变化”严格表示“随采样序号推进的变化”，不是 wall-clock 时间。
`record` 热路径不会做符号化；raw 文件中的 `top` 和 `stack` 只保存地址，
人类可读函数名全部由 `report` 离线解析。

帮助：

```bash
./build/pmi -h
./build/pmi record -h
./build/pmi report -h
```

## Raw 样本格式

`record` 输出的是以 tab 分隔的文本记录：

不带 `-e` 时，每行形如：

```text
S <seq> <insn_delta> <pid> <tid> <top> <stack>
```

带 `-e r0010,r0011` 时，每行形如：

```text
S <seq> <insn_delta> <pid> <tid> <r0010> <r0011> <top> <stack>
```

- `seq`：从 1 开始递增的样本序号
- `insn_delta`：同一个 `tid` 相邻两次样本之间退休的指令数
- `top`：叶子地址；如果未指定 `-s`，则为 `-`；`report` 会把它解析成函数名
- 每个 `-e` 事件都会展开为一个独立的 delta 列，列名就是原始事件名，例如
  `r0010` 或 `r0011`
- `stack`：在未指定 `-s` 或指定 `-s top` 时为 `-`；在 `-s full` 时，
  记录叶子帧之后剩余的原始调用链 IP，例如 `0xaaa;0xbbb`

对每个 `tid` 来说，第一条样本会直接把当前计数器值写成 delta。

文件头固定为：

```text
# pmi raw v3
```

`report` 只读取这个 v3 格式。
raw 文件始终保持 TSV，不做对齐；只有 `report` 会做对齐后的可读化展示。

## 当前限制

- 仅支持 Linux/arm64
- 仅支持 CPU core PMU 的原始事件
- `-e` 依赖真实 CPU PMU；没有 CPU PMU 的虚拟环境会直接失败
- `record --pid` 会周期性刷新线程列表，但不会在进程退出后保留完整的
  symbol/mmap 历史
- `record --pid` 和 `record --cmd` 默认每 `1000ms` 刷新一次线程列表
- 不加 `-s` 时不会输出函数和栈信息
- `--stack full` 依赖 `PERF_SAMPLE_CALLCHAIN`；用户态调用链质量取决于目标程序
  是否保留 frame pointer
- 录制阶段只保存原始栈地址，后续由 `report` 这类离线消费者做符号化
