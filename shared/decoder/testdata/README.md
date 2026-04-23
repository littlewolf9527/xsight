# packet-fixtures.json — cross-repo byte-compat contract fixtures

**目的**：给 xSight 的 decoder 定义 + xdrop 的 decoder 匹配原语建立机械化的字节级对齐机制。一份 fixture、两边 consume；任一方实现偏离 → CI 立刻打脸。

## 契约所有权

- **xSight 仓持有真相源** (这个文件)
- xdrop 仓通过 submodule / copy / 共享 repo 机制拉取，但**不修改**
- 语义定义发生变化（`xsight.c` decoder 逻辑改动）→ 先改 fixture + xSight 侧测试 → 再改 xdrop

## Schema

```json
[
  {
    "name": "unique_string_identifier",
    "hex": "hex_encoded_packet_bytes_starting_from_eth_or_ip_header",
    "frame_type": "ethernet" | "ip",
    "expected_decoders": ["tcp", "tcp_ack"],
    "expected_is_invalid": false,
    "expected_is_bad_fragment": false,
    "notes": "context on why this fixture exists, especially edge cases"
  }
]
```

### 字段

- `name`：全局唯一字符串（下划线风格）。约定前缀： `tcp_`, `udp_`, `icmp_`, `gre_`, `esp_`, `igmp_`, `frag_`, `invalid_`, `pod_`（PoD fragment）
- `hex`：数据包字节（十六进制字符串，无分隔符）。若 `frame_type=ethernet`，从 L2 开始；若 `ip`，从 IP header 开始
- `frame_type`：`"ethernet"` 或 `"ip"`。xSight / xdrop 两边的 parse 入口可能不同
- `expected_decoders`：xSight `DECODER_SWITCH` 应该增加计数的 decoder name 集合（不含 additive 标签如 fragment/anomaly）
- `expected_is_invalid`：xSight `parse_ip` 输出 `is_invalid` 的 bool 期望值
- `expected_is_bad_fragment`：xSight `parse_ip` 输出 `is_bad_fragment` 的 bool 期望值
- `notes`：一行注释说明 fixture 的存在理由 / 边界值 / 反例语义

## 覆盖要求（xdrop v2.6 proposal 规定）

每个 decoder 至少：
- **1 正例**：最典型的命中包
- **1 正例变体**：易被误读排除的形态（如 `tcp_ack_with_psh` — ACK flood 主要攻击面）
- **1 反例**：语义上相邻但契约排除的包（如 `tcp_syn_ack` — 握手第 2 包不算 tcp_ack）
- **边界值**（Phase 4 相关的 anomaly decoder）：PoD `frag_end=65535` vs `65536`；tiny TCP payload 19 vs 20；IHL 4 vs 5；TCP doff 4 vs 5

## 生成方式

**不手写 hex**。`generate.go` 用纯 Go 标准库（`encoding/binary` + `encoding/hex`）构造字节。不依赖 scapy / gopacket，避免给 shared 包引入外部依赖。

```bash
cd xsight/shared/decoder/testdata
go run generate.go
```

目录下当前没有 `//go:generate` 指令 —— 这是一次性生成器，fixture 期望跟着 `shared/decoder/contract_test.go` 里 `allTestFixtures()` 同步维护。两边任何一侧改动都应手动 `go run generate.go` 再 `go test ./shared/decoder/...` 走一遍 `TestFixtureJSONInSync`。

生成器由 `xsight.c` 的 DECODER_SWITCH + parse_ip 语义驱动（Go 侧 parity 实现在 `contract_test.go:goParityParse`）。若 `xsight.c` 改动：
1. 改 `contract_test.go:allTestFixtures` 期望
2. 同步 `generate.go` 的对应 fixture 定义
3. `go run generate.go` 更新 `packet-fixtures.json`（会把 `version` 往上推）
4. `go test ./shared/decoder/...` 验证 `TestGoParityMatchesFixtures` + `TestFixtureJSONInSync` 都过

## 两边消费

- **xSight 侧**：`shared/decoder/contract_test.go`（Go 侧实现 parity，assert `expected_decoders`）
- **xdrop 侧**：`node/agent/bpf/decoder_contract_test.go`（integration tag，CAP_BPF）— 下发对应 decoder 的 rule 后发 fixture 包，assert BPF 命中与否

## 当前状态

2026-04-23：已落地。`generate.go` + `packet-fixtures.json` (version 1, 33 fixtures) 在仓。xSight 侧 `TestFixtureJSONInSync` 绿，锁住了 on-disk 契约。xdrop 侧 integration test 待 xdrop v2.6 Phase 0 完成后接上。
