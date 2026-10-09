# Rust full / minimal 版本

`full` 是默认 feature，保留完整迁移功能；`minimal` 对齐 [Go 最小版](https://github.com/xfy-see/mosdns) 的 site-only 场景，复用 DNS Message、query context、domain matcher、sequence、内存/lazy cache 与 UDP/TCP 实现。两个 feature 互斥，minimal 必须关闭默认 feature。

## 能力范围

| 能力 | full | minimal |
|---|---|---|
| 配置格式 | YAML / YML / JSON / TOML | YAML / YML / JSON |
| 插件 | 现有完整 Rust 注册表 | `domain_set`、`cache`、`forward`、`sequence`、`udp_server`、`tcp_server` 六种 |
| 匹配与执行 | 现有完整能力 | `qname`、`has_resp`、sequence 内置动作和 `nftset` 快捷执行器 |
| DNS 上游 | UDP/TCP、DoT、DoH、HTTP/3、DoQ | 数字 IP 的 UDP/TCP，保留 UDP 截断后的 TCP 回退 |
| 上游路由约束 | socket mark / 绑定接口 | socket mark / 绑定接口 |
| 缓存 | 内存、lazy cache、磁盘 dump、HTTP 管理接口 | 内存、lazy cache；无 dump 或业务指标计数 |
| HTTP API / 指标 | 现有 API、业务与进程指标 | 不支持 API，不创建或更新业务指标 |
| SOCKS / bootstrap | 支持 | 不支持 |
| CLI | 现有 start/check/version、服务和工具命令 | 前台 start、check、version、帮助 |

`qname`、`has_resp`、`_true` 和 `_false` 是匹配器。sequence 快捷执行器保留 `accept`、`reject`、`return`、`jump`、`goto`、`forward`、`cache`、`nftset`；`nftset` 不增加插件类型数量。

最小版明确拒绝 HTTP API、非空 `dump_file`、任意非零 `dump_interval`（包括负值）、TCP listener 的非空 TLS cert/key、加密 DNS 协议、非数字 IP 上游及 SOCKS/bootstrap 配置。它不包含 `ip_set`、`resp_ip` 等完整能力；CN-IP 网站流量分流由外部 nftables 和路由规则承担。最小版没有 protobuf/gzip cache dump 路径，业务指标 collector 没有计数或标签存储；完整版本的 dump、公开指标接口及行为仍保留。

Rust full 继续支持 TOML；作为外部基线的 Go full 配置格式为 YAML/YML/JSON，不能据此认为两个 full 版本的范围完全相同。其他迁移边界仍见 [Rust 迁移说明](../rust/MIGRATION.md)。

## GitHub 构建

本地只修改和静态检查，push 后由 [.github/workflows/build.yml](../.github/workflows/build.yml) 编译，不在本地安装或执行 Cargo。工作流矩阵覆盖 macOS ARM64、Linux x86_64 musl 和 Linux ARM64 musl 的两个版本，正式 CLI 与 test harness 分开构建。下面是 CI 内的 feature 选择方式，供审查工作流使用：

```sh
# full 的正式 CLI
cargo build --locked --release -p mosdns-rs --bin mosdns-rs

# minimal 的正式 CLI
cargo build --locked --release -p mosdns-rs --bin mosdns-rs \
  --no-default-features --features minimal
```

不要只加 `--features minimal`，那会同时启用默认 full。Cargo test 的 feature 合并可能生成不同 CLI；正式 binary 必须来自普通 `cargo build --bin` 的本 profile 记录。不同 target/profile 使用独立产物目录。

产物名为 `mosdns-rs-<target>-<profile>-<完整commit SHA>`，包含 `manifest.json`、`bin/mosdns-rs`、测试 harness、冻结的 `runtime-source/`、日志与测试列表。使用 [下载与测试工具](../ci/download-and-test.py) 核实精确 commit、target/profile、大小与 SHA-256，并在本机/设备实际运行；完整步骤见 [GitHub 构建与测试](github-workflow.md)。CI 编译与测试通过不代替本机或设备验证。

[build-rust-profiles.py](../benchmarks/build-rust-profiles.py) 与 musl CC/AR wrapper 保留为历史冻结构建工具，要求 CI 环境事先准备好工具链、target 与依赖缓存。该脚本使用 offline Cargo、独立输出目录、source snapshot 与产物 manifest；它不会安装工具链，也不构成恢复本地 Rust 环境的指令。当前标准产物以 GitHub workflow 的清单与精确 commit 为准。

## 配置检查与 site-only 运行

minimal 的 `check` 读取配置与 include，解码并检查支持的插件/参数；不初始化插件、不写日志/dump、不监听网络、不操作 nftables。它不验证规则文件内容、接口、上游可达性或 nft 集合可用性。full 的 `check` 会初始化插件，可能创建日志、读取/保存 dump，且不等同于 listener 或 TLS 启动成功。

```sh
/absolute/path/to/mosdns-rs check -c /absolute/path/config.yaml
/absolute/path/to/mosdns-rs start -d /absolute/path/config-directory -c config.yaml
```

运行样例见 [根 README](../README.md#使用下载的可执行文件)。实际 site-only 策略需要准备 CN site 规则文件、可用的数字 IP DNS 上游、直连接口/隧道、已有的 nft IPv4/IPv6 集合与对应 mark 路由。`so_mark`、`bind_to_device`、`nftset` 需要 Linux 权限；程序不会自行创建接口、集合、隧道或路由，也不会替用户决定隧道故障时的泄漏策略。CN-IP 网站流量分类由外部 nftables/路由完成；minimal 不使用 `ip_set/resp_ip` 查询分支。

## 运行验证与历史记录

GitHub 对两个 profile 执行各自 fmt/Clippy/测试并提供 harness。本机下载后完整运行对应 native 的全部普通测试；Linux ARM64 下载校验后在用户指定的 `192.168.100.131` 独立运行 CLI、harness、协议与性能测试。完整性能验证需要固定 binary、fixture、配置和规则，覆盖 hot/cold/disabled cache、UDP/TCP、mock 分流与真实 DNS、并发及重复轮次。

权限 opt-in 用例默认 ignored，单独报告实际运行、读回与清理；普通通过不能证明 nftset、IPSet、socket mark/接口绑定或 Windows SCM 已执行。每轮保留 commit/artifact SHA、boot ID、原始结果、错误、延迟、RSS、体积和前后状态，不用旧产物或历史数字代表新的 commit。

2026-10-09 的迁移阶段体积、回归与 131 性能报告留在原 Go checkout 的 `optimization/rust-profiles-20261009/`；更早报告在其 `deployments/`。这些本地部署数据未上传到独立仓库。历史报告只绑定各自源码和二进制。
