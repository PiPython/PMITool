# PMITool 代码开发说明

本文档面向继续开发 PMITool 的工程人员，说明当前代码结构、核心数据流、接口约束和开发注意事项。

## 1. 项目定位

PMITool 是一个基于 `perf_event_open` 的 Linux/arm64 PMI 采样工具。当前主路径是纯 perf 实现：

- 使用 `PERF_COUNT_HW_INSTRUCTIONS` 作为 leader event，按退休指令数周期触发 sample。
- 用户通过 `-e rXXXX` 指定 CPU core PMU raw sibling events。
- 使用 `PERF_SAMPLE_READ` 在 leader sample 中带出整组计数。
- 使用 `PERF_SAMPLE_CALLCHAIN` 支持 `-s full` 调用链采集。
- `record` 热路径只做 perf ring 解码、delta 计算和异步写盘，不做符号化。
- `report` 离线完成符号化、C++ demangle、聚合和可视化。

## 2. 目录结构

```text
include/pmi/       公共头文件
src/main.c         子命令分发
src/record.c       record CLI、采样目标管理、主循环
src/perf_session.c perf_event_open、mmap ring drain、sample 解码、delta 计算
src/event.c        CPU PMU sysfs 解析和 raw event 转换
src/output.c       raw v3 异步 writer
src/report.c       raw v3 解析、报表、visual HTML 生成
src/symbolizer.c   /proc/<pid>/maps + ELF 符号解析 + demangle 支撑
src/procfs.c       /proc 辅助函数
tests/             单元测试
fixtures/          单元测试使用的最小 sysfs fixture
```

当前默认构建不依赖 libbpf、bpftool、CO-RE 或 libelf。

## 3. record 数据流

`record` 的关键路径如下：

```text
CLI 解析
  -> 解析目标：-p / -t / -c / -C 四选一
  -> 解析 raw PMU 事件：-e r0010,r0011
  -> 建立一个或多个 pmi_perf_session
  -> poll leader fd
  -> drain perf mmap ring
  -> 解码 PERF_RECORD_SAMPLE
  -> 按 event id 归一化 group read slot
  -> 按 session 计算 insn_delta / event delta
  -> 转成 pmi_output_sample
  -> 异步 writer 写 raw v3
```

采样目标由 `struct pmi_perf_target` 表示：

- `PMI_PERF_TARGET_TID`：调用 `perf_event_open(attr, tid, -1, ...)`。
- `PMI_PERF_TARGET_CPU`：调用 `perf_event_open(attr, -1, cpu, ...)`，用于 `-C 1-4` 这类 system-wide per-CPU 采样。

`-C` 模式内部会为每个 CPU 建立独立 session，但 raw 输出不保留 CPU 列，所有 sample 进入同一个 writer 队列并分配全局 `seq`。

## 4. perf session 开发约束

`src/perf_session.c` 是采样正确性的核心文件，修改时需要遵守以下约束：

- leader event 固定为 `PERF_COUNT_HW_INSTRUCTIONS`。
- sibling events 必须加入 leader group。
- `sample_type` 至少包含 `IP/TID/TIME/CPU/READ/STREAM_ID`。
- `-s full` 时才启用 `PERF_SAMPLE_CALLCHAIN`。
- `PERF_SAMPLE_READ` 解码后必须按 event id 归一化到 session slot，再计算 delta。
- slot 0 固定是 `instructions`，slot 1..N 固定对应 `-e` 输入顺序。
- delta 是按 session 维护的；TID 模式 session 对应 tid，CPU 模式 session 对应 CPU。
- record 热路径不得加入符号化、demangle、procfs 高频读取或大规模动态分配。

## 5. raw v3 输出约定

raw 文件是 TSV 文本，文件头固定：

```text
# pmi raw v3
```

无自定义事件时列为：

```text
type seq insn_delta pid tid top stack
```

有自定义事件时列为：

```text
type seq insn_delta pid tid r0010 r0011 top stack
```

字段语义：

- `seq`：全局样本序号，从 1 递增。
- `insn_delta`：当前 session 相邻两次样本的 instructions delta。
- `pid/tid`：sample 触发时 perf 提供的任务信息。
- 动态事件列：`-e` 指定 sibling event 的 delta。
- `top`：未指定 `-s` 时为 `-`；`-s top/full` 时为叶子 IP 地址。
- `stack`：仅 `-s full` 时写叶子帧之后的 raw IP 列表。

raw 文件不做列对齐、不做符号化、不做 C++ demangle。所有可读化展示都放在 `report`。

## 6. report 数据流

`report` 负责离线处理：

- 读取 raw v3 表头，动态识别事件列。
- 支持 `overview`、`samples`、`visual` 三种模式。
- 支持 `-t tid1,tid2` 过滤。
- 将 raw 地址解析成函数名。
- 对 C++ mangled 名做 best-effort demangle。
- `overview` 做热点聚合和 folded stack 聚合。
- `samples` 按 raw 顺序逐条展示。
- `visual` 生成单文件 HTML，用阶段热条图展示热点阶段变化。

`report` 可以做较重工作，`record` 不应重复这些逻辑。

## 7. 新功能开发建议

新增采样相关能力时优先检查这几个问题：

- 是否会增加 record 热路径成本。
- 是否会改变 raw v3 schema。
- 是否能通过 report 离线实现，而不是 record 实时实现。
- 是否需要新增 `perf_event_attr` 字段，字段顺序是否影响 sample 解码。
- 是否需要更新 `tests/` 中的 decode、output、report、CLI/parser 测试。
- 是否需要更新 README 和本文档。

新增 CLI 参数时需要同步更新：

- `record_usage()` 或 `report_usage()`。
- `README.md`。
- 对应 parser 单元测试。
- 错误信息，必须 fail fast，不能静默忽略非法输入。

## 8. 编码规范

- 语言使用 C11。
- 构建使用手写 `Makefile`。
- 默认开启 `-Wall -Wextra -Werror`。
- 修改文件时保持 ASCII，除中文文档和已有中文注释外不引入额外 Unicode。
- 注释只解释非显然逻辑，避免重复代码含义。
- 不要引入 Go/Rust/Python runtime 作为工具运行依赖。
- 不要把 Linux-only 代码改成 macOS 兼容分支；macOS 只作为编辑环境。
