# PMITool 软件代码重构说明

本文档说明 PMITool 当前代码重构后的设计取向、模块边界和后续重构原则。

## 1. 重构目标

PMITool 的核心目标是低开销 PMI 采样。当前代码已经收敛到纯 `perf_event_open` 路径，重构目标包括：

- 降低 `record` 对业务线程的额外影响。
- 避免采样时做符号化、demangle、复杂 join 或重型字符串处理。
- 保持 raw 文件格式简单、稳定、可离线处理。
- 把展示、聚合、符号化和可视化全部后移到 `report`。
- 保留清晰模块边界，避免历史方案和当前主路径并存。

## 2. 当前重构结果

### 2.1 采样模型收敛

当前实现不再依赖 BPF 参与采样主路径。所有数据来自同一个 perf sample 流：

- 指令 PMI 触发来自 leader instructions event。
- 自定义 PMU 值来自 sibling group read。
- 调用链来自 `PERF_SAMPLE_CALLCHAIN`。
- `pid/tid/cpu/ip/time/stream_id/read` 都由 perf sample 解码得到。

这样避免了 perf sample 与 BPF ringbuf 的实时 join，也减少了丢包、乱序和匹配失败风险。

### 2.2 record 热路径瘦身

`record` 热路径只保留必要操作：

- drain perf mmap ring。
- 解码 `PERF_RECORD_SAMPLE`。
- 按 event id 归一化 read slot。
- 计算 session 内 delta。
- 提取 top IP 和 stack IP。
- 入队给异步 writer。

明确不在 record 热路径执行：

- ELF 符号化。
- C++ demangle。
- 每帧 stack 符号解析。
- 高频 procfs 读取。
- 大量动态分配。
- HTML 或报表生成。

### 2.3 异步写盘

`src/output.c` 使用有界队列和后台 writer 线程：

- 默认 `low-overhead`：队列满时丢弃 userspace 样本，优先减少对采样主循环的阻塞。
- `strict`：队列满时等待空间，尽量不丢 userspace 样本。
- writer 批量格式化 TSV 并写文件。

这把文本拼装和文件 I/O 从采样主循环里移出去，降低对业务性能的干扰。

### 2.4 report 离线增强

`report` 接管较重逻辑：

- 地址到函数名解析。
- C++ demangle。
- overview 聚合。
- samples 顺序展示。
- full stack folded 聚合。
- visual HTML 生成。
- 表格对齐和长文本截断。

这种分工保证 record 生成“足够正确的原始数据”，report 负责“人类可读和分析体验”。

## 3. 模块边界

### record.c

职责：

- CLI 参数解析。
- 采样目标管理。
- `-p/-c` 模式线程刷新。
- `-C` CPU 范围展开和 per-CPU session 建立。
- poll/drain 调度。
- 把 perf sample 转成轻量 `pmi_output_sample`。

不应承担：

- 符号化。
- 报表聚合。
- PMU sysfs 细节解析。
- raw 文件具体格式化细节。

### perf_session.c

职责：

- 构造 `perf_event_attr`。
- 调用 `perf_event_open`。
- 管理 leader/sibling fd 和 mmap ring。
- 解码 sample。
- 归一化 read slot。
- 计算 delta。
- 输出 debug-perf 诊断日志。

这是采样正确性的核心模块。修改时需要优先保证 `PERF_SAMPLE_*` 解码顺序、group read slot 和 delta 语义不被破坏。

### event.c

职责：

- 从 `/sys/bus/event_source/devices` 找 CPU core PMU。
- 解析 `format/event`。
- 将 `r0010` 这类 raw token 转成 `perf_event_attr` 所需字段。
- 拒绝 uncore、tracepoint、software 等非目标 PMU。

### output.c

职责：

- 维护异步 writer。
- 输出 raw v3 TSV。
- 保持动态事件列顺序与 `-e` 输入一致。

不应在这里做符号化或业务语义推断。

### report.c

职责：

- 解析 raw v3 schema。
- 按 TID 过滤。
- 符号化和 demangle。
- 输出 overview/samples/visual。
- 表格格式化。

report 可以牺牲一部分 CPU 和内存换取可读性，因为它不在采样热路径。

## 4. 已解决的关键问题

- 去掉采集时 perf/BPF join，降低链路复杂度。
- raw 输出从累计值改为 delta，便于直接做阶段和热点统计。
- 动态事件列从单个 `events` blob 改为独立列，解决多事件对齐和解析问题。
- `record` 热路径不再符号化，避免 `-s full` 时卡死或明显拖慢。
- `report` 增加 C++ demangle，提高 C++ 程序可读性。
- `report` 表格输出做宽度计算和长文本截断，避免终端错位。
- `visual` 从逐 sample 散点改为阶段热条图，降低大样本 HTML 的渲染成本和阅读成本。
- `-C` CPU 范围采样内部多 session，外部保持统一 sample 流。
- `PERF_SAMPLE_READ` 按 event id 归一化，避免 read slot 与输出列错位。

## 5. 后续重构原则

### 5.1 优先保护 record 热路径

任何新增能力都应先判断能否在 report 离线完成。只有必须依赖内核采样现场的数据，才应进入 record。

不建议加入 record 热路径的能力：

- 源码行号解析。
- DWARF unwind。
- C++ demangle。
- JSON/HTML 输出。
- 复杂聚合。
- 高频 `/proc` 或 `/sys` 扫描。

### 5.2 schema 变化要谨慎

raw v3 是当前 report 和 visual 的输入契约。修改 schema 时必须同步修改：

- `output.c`
- `report.c`
- `tests/test_output_v3.c`
- `tests/test_report_v3.c`
- README
- 文档

如果只是新增展示能力，优先不要修改 raw schema。

### 5.3 perf attr 修改必须配套 decode 测试

任何 `sample_type` 变化都会影响二进制 sample 解码顺序。修改后必须补充 `tests/test_perf_decode.c`。

特别注意：

- `PERF_SAMPLE_*` 字段必须按内核定义顺序解码。
- `PERF_SAMPLE_READ` 的 group read 格式必须和 `read_format` 一致。
- `PERF_SAMPLE_CALLCHAIN` 要过滤 `PERF_CONTEXT_*` marker。

### 5.4 CPU 模式不暴露 CPU 维度

当前产品语义是多个 CPU 直接聚合成一个 sample 流。后续如果需要 CPU 维度，应作为显式新功能增加，例如 `--include-cpu-column`，不能默认改变当前输出。

### 5.5 删除历史代码优先于保留分支

仓库应保持当前产品主路径清晰。已经不参与构建和测试的历史方案不应长期保留为“备份代码”。需要保留设计背景时，用文档或 git 历史即可。

## 6. 建议的后续优化方向

- 增加 Linux CI，至少覆盖 openEuler 或 Ubuntu arm64/x86_64 构建和单测。
- 为 `perf_event_open` 增加可注入 wrapper，进一步扩大无需 root 的单元测试覆盖。
- 评估二进制 raw spool 格式，在样本量极大时降低写盘和文件体积。
- 增加 report 的导出格式，例如 folded stack、CSV 或 JSON。
- 对 visual HTML 做数据压缩，降低大样本文件体积。
- 在 README 中明确不同 PMU raw event 在不同 ARM 平台上的兼容性差异。
