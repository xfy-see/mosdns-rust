# mosdns-rust

mosdns-rust 是 [mosdns v5 Go 实现](https://github.com/xfy-see/mosdns) 的 Rust 重写。项目保留 `coremain → plugin → pkg` 模块、YAML plugin/sequence 配置与 query context 执行模型，先复用和补充行为测试，再优化体积和性能。

Rust 后续独立在 [xfy-see/mosdns-rust](https://github.com/xfy-see/mosdns-rust) 开发。开发方式固定为：**本地修改与静态检查 → 提交并 push → GitHub Actions 编译 → 下载对应 commit 的产物 → 本机与目标设备完整测试校验**。本地不安装 Rust 工具链，也不执行 Cargo 编译。详细流程见 [GitHub 构建与测试](docs/github-workflow.md)，维护规则见 [AGENTS.md](AGENTS.md)。

## 两个版本

| 能力 | full（默认） | minimal |
| --- | --- | --- |
| 配置 | YAML/YML、JSON、TOML | YAML/YML、JSON |
| DNS 上游 | UDP/TCP、DoT、DoH、HTTP/3、DoQ | 数字 IP 的 UDP/TCP，含 UDP 截断后 TCP 回退 |
| DNS listener | UDP/TCP、TLS、HTTP/HTTPS、QUIC | UDP/TCP |
| 插件与匹配 | 完整迁移注册表，含 domain/IP、fallback、EDNS、API 与指标 | `domain_set`、`cache`、`forward`、`sequence`、`udp_server`、`tcp_server`；`qname`、`has_resp` 等基础匹配 |
| 缓存 | 内存、lazy cache、磁盘 dump、HTTP 管理 | 内存、lazy cache |
| CLI | 运行、配置检查、服务与配置/probe 工具 | 前台运行、配置检查、版本与帮助 |

minimal 面向 site-only DNS 分流，保留 `nftset` 快捷执行器及 Linux socket mark/接口绑定。它不提供 `ip_set`、`resp_ip`、HTTP API、磁盘 dump、加密 DNS、SOCKS 或 bootstrap；CN-IP 网站流量策略由外部 nftables 和路由规则承担。两个 feature 互斥。完整参数与拒绝项见 [版本说明](docs/rust-profiles.md)，业务兼容边界见 [迁移说明](rust/MIGRATION.md)。

## 使用下载的可执行文件

GitHub 构建产物含正式 CLI、测试 harness、源文件快照、构建日志与逐文件 SHA-256 清单。先按 [下载与校验流程](docs/github-workflow.md) 验证 commit、架构、版本和摘要，再运行对应平台的 CLI：

```sh
/absolute/path/to/mosdns-rs version
/absolute/path/to/mosdns-rs check -c /absolute/path/config.yaml
/absolute/path/to/mosdns-rs start -d /absolute/path/config-directory -c config.yaml
```

相对 include、规则文件和日志路径按工作目录解析。程序不会通过 `start` 自动配置系统 DNS、路由、接口或 nftables 集合。以下配置可用于 full/minimal 的独立 UDP/TCP 测试端口：

```yaml
log:
  level: info
plugins:
  - tag: cached
    type: cache
    args:
      size: 1024
  - tag: upstream
    type: forward
    args:
      concurrent: 1
      upstreams:
        - addr: udp://223.5.5.5
  - tag: main
    type: sequence
    args:
      - exec: $cached
      - matches: has_resp
        exec: accept
      - exec: $upstream
  - type: udp_server
    args:
      listen: 127.0.0.1:15353
      entry: main
  - type: tcp_server
    args:
      listen: 127.0.0.1:15353
      entry: main
```

```sh
dig @127.0.0.1 -p 15353 example.com A
dig @127.0.0.1 -p 15353 example.com A +tcp
```

full 的 `check` 会初始化插件，可能读取/保存配置指定的 cache dump 或创建日志文件；minimal 的 `check` 只解析与验证支持的配置，不初始化插件。两者都不证明上游、接口、nftset 或实际路由可用。更多运行和 library API 用法见 [Rust 说明](rust/README.md)。

## 代码与测试

```text
Cargo.toml / Cargo.lock        workspace 与锁定依赖
rust/src/coremain/             配置、Engine、Registry、生命周期
rust/src/plugin/               matcher、sequence、可执行插件
rust/src/pkg/                  DNS、缓存、上游、listener、内核 set 等组件
rust/tests/                    CLI、协议、生命周期与兼容回归
tests/fixtures/                与 Go 共用的行为输入和预期结果
ci/                            GitHub 产物打包、下载校验及本地测试工具
.github/workflows/build.yml    GitHub 编译与质量检查
```

TLS mock 所需证书与私钥不作为固定文件提交。GitHub Actions 编译前由 [generate-test-fixtures.py](ci/generate-test-fixtures.py) 临时生成相同测试路径的本轮素材；harness 只内嵌一次性的 localhost mock 输入。两个生成私钥文件在编译后删除，不以独立文件进入源码快照或 artifact；四个公开测试证书可供运行测试使用。manifest 的 `generated_test_inputs` 单独记录路径、大小与 SHA，区别于 Git 已跟踪源码。真实设备凭据始终不进入源码、日志或产物。

GitHub 为 macOS ARM64、Linux x86_64 musl 与 Linux ARM64 musl 构建 full/minimal，并执行对应测试；下载的 native harness 仍需在本机完整运行，Linux ARM64 harness 与 CLI 需在 `192.168.100.131` 做实际回归、socket/nftset 验证和完整性能测试。CI 通过、交叉构建通过和设备实测分别记录；默认 ignored 的权限用例逐项列明。

[ci/test-router.py](ci/test-router.py) 校验本 commit 的 ARM64 artifact 和干净源码 checkout，逐个在 131 执行完整普通 harness，并由 [router-session.sh](ci/router-session.sh) 监控、核对 boot/PID/可执行文件归属及清理。默认仅生成计划，`--execute` 才运行；`--nft` 和 `--socket-options` 分别显式执行隔离 nftset 读回和 socket 权限用例。`--ipset-probe` 只查询 IPSet subsystem 能力，不创建 set；131 历史缺少 IPSet 支持，若查询失败单独记录为 capability 失败/不可用，不算通过，也不证明 IPSet 元素互操作。

迁移阶段的报告和部署证据保留在原 Go checkout 的 `deployments/` 与 `optimization/`，不上传到此独立源码仓库，也不把历史性能当作新 commit 的验证。当前 Rust 改动仅提交到本仓库，Go 工作树作为外部兼容与性能基线。

## 许可证

本项目遵循 [GPL-3.0-or-later](LICENSE)。源文件保留原作者与许可证声明。
