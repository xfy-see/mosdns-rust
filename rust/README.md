# mosdns Rust 实现与 API

本目录是独立 [mosdns-rust](https://github.com/xfy-see/mosdns-rust) 仓库的 Rust crate，保留 Go 的 plugin、matcher、sequence 和 query context 模型。根 Cargo workspace 只包含 `rust/`；Go 源码作为[外部兼容基线](https://github.com/xfy-see/mosdns)。实现范围与已知差异见 [MIGRATION.md](MIGRATION.md)。

这里的功能说明以 **full** 为主。minimal 的插件、协议和 CLI 范围见 [版本说明](../docs/rust-profiles.md)，不应将下列完整能力全部用于 minimal。

## 构建与运行

本地只修改和静态检查；push 后在 GitHub 编译，再下载并完整校验/运行。具体流程见 [GitHub 构建与测试](../docs/github-workflow.md)。本地不安装 Rust 工具链，也不执行 Cargo 编译。以下使用已下载并校验的对应平台 full CLI：

```sh
/absolute/path/to/mosdns-rs version
/absolute/path/to/mosdns-rs check -c /absolute/path/config.yaml
/absolute/path/to/mosdns-rs start -c /absolute/path/config.yaml
```

`check` 加载配置、规则文件、插件和引用，但不监听 DNS 端口，也不验证上游可达性。配置按扩展名支持 YAML/YML、JSON、TOML。它会初始化 logger 和缓存，因而可能创建配置指定的日志文件，读取 `dump_file`，并在显式关闭时保存缓存。TLS listener 的证书内容与端口占用仍需启动时验证。

相对路径以进程工作目录为基准，与 Go 的 `-d` 语义一致；相对的 `include` 和规则文件不会自动改成相对于主配置文件的位置：

```sh
/absolute/path/to/mosdns-rs start -d /absolute/path/config-directory -c config.yaml
```

未指定 `-c` 时读取 `config.yaml`。`--cpu N` 配置 Tokio worker 数，非正数沿用默认；它不设置 CPU affinity，也不限制独立的 blocking worker。Unix 的 `--as-service` 保持前台运行，由服务管理器监督。SIGINT、Unix SIGTERM、listener 失败或插件关闭信号都会停止 listener，等待已进入的查询和后台任务，保存缓存，再调用关闭钩子。原始错误与清理错误一并返回。Windows 的 `start --as-service` 使用原生 SCM dispatcher，`--service-name NAME` 对应安装名称；STOP/PRESHUTDOWN 进入同一清理流程。Windows 原生接口已交叉编译检查，尚未实机验证 SCM。

这是一个可直接运行的 UDP/TCP 示例，监听本机的独立测试端口：

```yaml
log:
  level: info
api:
  http: 127.0.0.1:19091
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

保存为自己的配置文件后启动，再用相同 query 检查 UDP 和 TCP：

```sh
dig @127.0.0.1 -p 15353 example.com A
dig @127.0.0.1 -p 15353 example.com A +tcp
```

`matches` 支持单个字符串或列表；列表成员是 AND，`!` 取反。`qname` 支持内联规则、`$domain_set_tag` 和 `&file`；`client_ip`、`resp_ip`、`ptr_ip` 对应支持 IP set 和文件。确定性的 CN site/CN IP 分流样例与两语言共用结果见 [split.yaml](../tests/fixtures/split.yaml) 和 [split_cases.json](../tests/fixtures/split_cases.json)。该 fixture 用于测试 Engine，不包含 listener。

## 配置工具与服务定义

保留 Go 的顶层 `config` 和 `probe` 命令，另接受 `tools` 前缀。生成和转换均要求输出文件尚不存在：

```sh
/absolute/path/to/mosdns-rs config gen /absolute/path/new-config.yaml
/absolute/path/to/mosdns-rs config conv -i config.yaml -o /absolute/path/new-config.toml
/absolute/path/to/mosdns-rs probe conn-reuse tcp://127.0.0.1:15353
/absolute/path/to/mosdns-rs probe pipeline tcp://127.0.0.1:15353
/absolute/path/to/mosdns-rs probe idle-timeout tcp://127.0.0.1:15353 --timeout 30s
```

probe 支持 TCP/TLS，校验响应 question、ID、QR 和 opcode。TLS 使用证书与 server name 校验；idle probe 达到观察上限仍未关闭时，报告“至少保持打开多久”，不把该下限当作已测出的 idle timeout。收到完整且合法的 DNS 响应后，TLS peer 未发送 `close_notify` 就关闭也会计入关闭观察；DNS 响应被截断仍然报错。

TOML 的日期、时间和 datetime 转为规范文本标量，写回 TOML 时使用字符串；JSON/YAML 输出不包含 TOML 库内部的 datetime 字段。JSON 无法表示 NaN/Infinity，转换会明确报错，并且不创建输出文件。YAML/JSON 的 null 转 TOML 同样报错。这些工具修正有本机和 131 ARM64 回归测试；实机性能数据对应报告所冻结的构建和源码快照。

service 代码支持 systemd、macOS launchd 和 OpenWrt procd。先生成定义供检查，输出默认是 stdout；指定 `-o` 时不覆盖现有文件：

```sh
/absolute/path/to/mosdns-rs service generate --platform systemd --name mosdns-rs -d /absolute/config-dir -c config.yaml --cpu 2
/absolute/path/to/mosdns-rs service generate --platform launchd -d /absolute/config-dir -c config.yaml
/absolute/path/to/mosdns-rs service generate --platform procd -d /absolute/config-dir -c config.yaml
```

`service install/uninstall/start/stop/restart/status` 使用当前主机的服务管理器。默认名称是 `mosdns-rs`，与原 Go 的 `mosdns` 区分；安装不覆盖已有定义，后续操作只接受带本工具标记的定义。install 注册开机启动但不立即启动进程，start 单独执行。Windows 使用原生 SCM API，安装保留路径/参数并检查 display name 与 description 标记；`service generate --platform windows` 输出 argv 和 ImagePath 的 JSON 预览。当前仅验证生成、状态/控制模型和 Windows 交叉编译，尚未实际安装、运行或卸载系统服务。Windows 代码检查与测试在 GitHub CI 执行，不能当作实际 SCM 安装/控制证据。

## 已有覆盖

| 范围 | 当前实现 |
| --- | --- |
| 数据提供器 | `domain_set`、`ip_set`，内联规则、文件、组合 sets |
| 控制流 | `sequence`、`jump`、`goto`、`return`、`accept`、`reject`；带 tag 的 sequence 调用 |
| 匹配 | `qname`、`cname`、`client_ip`、`resp_ip`、`ptr_ip`、`qtype`、`qclass`、`rcode`、`has_resp`、`has_wanted_ans`、`mark`、`env`、`random`、`string_exp`、`_true`、`_false`；配置为 matcher 的 `rate_limiter` |
| 查询执行 | `forward`、`fallback`、`cache`、`hosts`、`arbitrary`、`redirect`、`ttl`、`black_hole`、`drop_resp`、`sleep`、`mark`；Linux 原生 `ipset`/`nftset` quick syntax，实机验证状态见下文 |
| EDNS 与双栈 | `ecs_handler`、旧的 `ecs` quick syntax、`forward_edns0opt`、`prefer_ipv4`、`prefer_ipv6` |
| 状态与观测 | `reverse_lookup` 的查询记录、PTR 和 HTTP lookup；`metrics_collector`、`query_summary`、`debug_print`；缓存 HTTP API |
| 上游协议 | UDP、TCP、DoT、DoH（HTTP/1.1、HTTP/2、HTTP/3）、DoQ；地址前缀 `udp://`、`tcp://`、`tcp+pipeline://`、`tls://`、`tls+pipeline://`、`https://`、`h3://`、`quic://`、`doq://`，无前缀默认为 UDP |
| DNS listener | `udp_server`、`tcp_server`；配置证书的 TCP listener 提供 DoT；`http_server` 提供 HTTP/HTTPS DoH；`quic_server` 提供 DoQ；TCP/HTTP 及其 TLS 形式支持 Unix socket |

表格同时列出独立 plugin 与 sequence quick syntax。具体注册位置和参数支持见 [迁移映射](MIGRATION.md#目录与接口映射)，不能将所有 quick syntax 名称都理解为 Go 支持的独立 `type:`。

上游连接复用、TCP/TLS pipeline、UDP TC 到 TCP fallback、DNS response ID/question 验证、TLS 证书与名称验证、DoH HTTP/2/HTTP/3、DoQ framing 均有本机 mock 回归测试。forward 已接入 `dial_addr`、`idle_timeout`、`enable_pipeline`、`enable_http3`、`insecure_skip_verify`、`socks5`、`bootstrap`、`bootstrap_version`、`so_mark`、`bind_to_device`；后两项只支持 Linux。`concurrent` 使用 Go 的 1 至 3 范围及首个可接受响应规则。普通 TCP/TLS 的 `enable_pipeline: false` 使用每连接一个查询的复用池，`+pipeline` 地址强制 pipeline；pipeline 连接可扩容，TCP/TLS 每连接 64、UDP 4096 in-flight；拨号上限 5 秒，pipeline 读健康 deadline 10 秒，独占复用 query 上限 6 秒。旧 pipeline 连接关闭会在原请求 deadline 内限定重试，新连接错误和活连接的 DNS 校验错误直接返回。UDP 每秒重传，TC→TCP 使用 direct reuse 和独立的默认 10 秒 idle timeout。DoH 保留配置 URL path，包括根路径 `/`。

DoT、DoH、DoQ、HTTP/3 和 TLS probe 共用系统 CA roots。Linux 按 Go 的系统文件与目录查找规则读取，非空 `SSL_CERT_FILE` 与 `SSL_CERT_DIR` 分别覆盖各自的默认列表；只指定一个仍保留另一个默认列表。roots 在进程内缓存，重启后重新读取。macOS 导入系统 trust roots 给 rustls，校验方式与 Go 的 SecTrust 仍有差异。有效 CA 会保留并报告跳过的坏项，没有有效 CA 时返回错误；没有内置 roots 备用。`insecure_skip_verify` 跳过 CA 加载和证书身份检查，但仍校验 TLS 握手签名。YAML 没有额外的 CA 参数，probe 始终严格验证。隔离私有 CA、错误身份及加载失败用例见 [system_trust.rs](tests/system_trust.rs)。

`http_server` 的 `entries` 使用 Go 的 `{path, exec}` 格式，支持 GET/POST DoH。TLS/QUIC 的 SNI 及 HTTP path 传入 `string_exp`，`src_ip_header` 可为 `client_ip` 提供来源地址。TLS listener 使用 PEM `cert` 和 `key`。

TCP/HTTP 的 `listen: '@name'` 保留 Go 语义：Linux 使用 abstract Unix namespace，macOS 使用带 `@` 的文件名。另可用 `listen: 'unix:///absolute/path/dns.sock'` 明确创建 filesystem socket，关闭 listener 时清理自己创建的 socket。Unix client 没有 IP；`client_ip` 不匹配，limiter 不扣 token，`ecs_handler.send` 不生成 client ECS，HTTP 来源 header 可补充实际 IP。Linux wildcard UDP listener 使用 packet info 保留正确回包源地址；IPv4、IPv6、dual-stack 与 abstract Unix 回归已在 131 的 Linux 上通过。

131 上两个隔离 nftset 内核用例已通过，覆盖 IPv4/IPv6、interval membership、set 默认 timeout 与显式 timeout readback。ipset 代码及 wire 测试已有，但该目标的 protocol-only 查询返回 `EINVAL`，模块清单、`/sys/module` 与 `/lib/modules` 未找到 IPSet 支持，未验证 ipset 真实添加成功。不能把 nftset 的成功推广到 ipset；后者仍需在支持 IPSet 的隔离 Linux 内核验证。

## Rust 插件扩展

作为 library 嵌入时，可使用 `coremain::Registry` 注册配置工厂、preset、exec 和 matcher quick setup，然后通过 `Engine::new_with_registry(config, registry)` 初始化。`Engine::new` 使用没有自定义扩展的默认 registry；CLI 不会动态加载共享库或从 YAML 中执行代码。注册名冲突返回错误，内建名称保留；注册表可克隆并由调用方独立维护，不使用 Go 的进程级 `init()` 全局注册。

下面的 quick setup 复用内建 executable，YAML 中可用 `exec: local_answer 192.0.2.1`：

```rust
use mosdns_rs::{coremain::{Config, Engine, Registry}, plugin::executable::Executable};

let mut registry = Registry::new();
registry.register_exec("local_answer", |_, args| {
    Ok(Executable::BlackHole(vec![args.parse()?]))
})?;
let engine = Engine::new_with_registry(Config::load(std::path::Path::new("config.yaml"))?, registry)?;
```

自定义逻辑实现 `ExecutablePlugin`、`RecursiveExecutablePlugin` 或 `MatcherPlugin`，由工厂返回对应的 `Executable::Custom`、`Executable::RecursiveCustom` 或 `Matcher::Custom`。这些接口返回可取消的 async future；matcher 错误会经过 AND/取反传出。递归 executable 通过 `Next::exec` 执行后续链，可在完成后处理响应，也可直接返回来终止链。`BuildContext` 提供自身 tag 与依赖 plugin 查找；`Plugin::Data` 可保存任意 `Send + Sync` provider；`Engine::get_plugin` 提供运行时查找。tag 调用的 `quick_configure` 对应 Go 的 quick-configurable 接口。

`Plugin::Custom(Arc<PluginObject>)` 可组合 executable、matcher、Any provider 与 `PluginCloser`，各能力可引用同一个 `Arc<T>`。工厂取得资源后立即调用 `BuildContext::register_closer(...)?`，失败或 panic 会回滚本次新资源；已被依赖或其它工厂持有的共享资源不会提前关闭。已回滚关闭的 Arc 不能在同一次初始化中再次注册。`attach_service` 的 future 在整体初始化成功后启动，应响应 `shutdown_signal` 并退出；服务错误或 panic 发出 Engine 关闭信号。

library 调用方应显式 `engine.shutdown().await?`。所有 Engine clone 共享关闭状态；关闭拒绝新查询，等待现有查询、lazy/fallback/selector/forward 背景任务和 attached service，停止并等待缓存清理器，显式关闭 upstream transport，再保存 dump、按初始化逆序调用去重的 closer。正常 closer 在 blocking worker 运行，启动回滚在构造器调用线程运行；错误或 panic 不跳过其余 closer。`Drop` 不执行关闭钩子，服务必须先结束再由 closer 释放资源；不同 Engine 共享同一个 Arc 时，调用方需确保全局幂等或避免共享。`request_shutdown`、`shutdown_signal` 和 `wait_closed` 对应主动请求、监听及等待关闭；取消某个等待 future 不取消已启动的关闭任务。测试见 [plugin_lifecycle.rs](tests/plugin_lifecycle.rs) 和实际 CLI [cli_lifecycle.rs](tests/cli_lifecycle.rs)。

`pkg::query_context::reg_key()` 返回初始化阶段使用的唯一非零 `u32`；旧的 `plugin::query_context` 路径继续 re-export 相同类型。查询 KV 支持 `store_value`、`store_shared_value`、`get_value`、`get_value_as` 和 `delete_value`。复制 QueryContext 时复制 KV map、共享 `Arc` value，覆盖/删除 key 不改变源 map；共享可变值应使用 Mutex 或 atomic。完整运行示例及错误、依赖和复制测试见 [plugin_registry.rs](tests/plugin_registry.rs)。动态 provider 和 BP 扩展见下文；平台限制见 [迁移限制](MIGRATION.md#尚未迁移或限制明确的功能)。

`PluginObject::domain_provider/ip_provider` 接受 `DomainMatcherProvider/IPMatcherProvider`；getter 在构建规则时取得一次同步 matcher 句柄，内部规则可通过锁或 atomic 更新。它们可以直接用于 `qname/cname/client_ip/resp_ip/ptr_ip`、`$tag` 和 set 组合，静态集合仍走原来的同步分支。接口和用例见 [plugin_providers.rs](tests/plugin_providers.rs)。

`BuildContext::register_api` 将 `PluginApi` 挂载到 `/plugins/<tag>`。handler 接收原始 method/URI/headers、最多 16 MiB body 和去掉 mount 后的相对路径，返回状态、headers 和 body。handler 自行路由；错误或 panic 返回 500，Engine 关闭时新请求返回 503，正在处理的请求在 closer 前 drain。API listener 仍需通过配置或 `api::serve_listener` 启动。

`BuildContext::metrics()` 返回带 `mosdns_` 前缀的实例级 registerer，可加 prefix/const labels，再登记 counter、gauge 或 histogram。重复 series、不一致 family、非法 label/bounds 和内建名称冲突返回错误；更新要求有限数值，counter 禁止负增量。histogram 默认使用 Prometheus 常见秒桶，传入显式 bounds 可用于其它单位；`/metrics` 输出 HELP/TYPE、累积 buckets、sum/count。目前未提供 vector/summary 或完整 Prometheus client API。

工厂的 API/metrics 注册与本次初始化一起提交；错误或 panic 会撤销本次登记，并禁止失败作用域留下的 registerer 再登记。失败序列之前成功的 quick setup 注册也会撤销，成功初始化的其它 tag 依赖继续保留；失败序列也撤销内建 collector、已完成 quick setup 的 closer 和未启动 service，tagged quick configure panic 转为初始化错误。整体启动失败会撤销所有作用域。API mount、请求语义与 Go 共用 [fixture](../tests/fixtures/plugin_api.json)，恢复和关闭测试见 [plugin_extensions.rs](tests/plugin_extensions.rs)。

`BuildContext::logger()` 提供按 tag 命名的 debug/info/warn/error logger，沿用 level/file/production 设置，JSON fields 保留类型，与查询日志共用文件锁。`level/msg/tag` 为保留字段，写入失败返回错误；不会自动请求 Engine 关闭。该接口没有逐一复刻 zap 的 fatal/panic 或采样行为。

## 缓存与 API

缓存保持“命中后继续执行后续规则，完成后写回”的递归行为。因此要终止命中后的 resolver，请保留示例中的 `has_resp` + `accept`。缓存恢复当前 query ID，按存储时间衰减 TTL，支持 Go 的负缓存 TTL 和 lazy cache 后台去重更新。

DNS cache、reverse lookup 与双栈 selector 复用 `pkg/cache`、`pkg/concurrent_map`，保持 Go 的 64 分片与任意淘汰设计。每个分片容量为 `size / 64`；正数小于 64 时不限制容量，非正数配置先采用对应插件默认值。DNS cache 和 reverse lookup 每 10 秒清理过期项，selector 每分钟清理。Rust 在释放分片读锁后克隆响应，Engine 显式关闭并等待这些清理器；Go 与 Rust 使用各自随机 hash，无法保证逐项相同的淘汰对象。

`dump_file` 使用 Go 的 `mosdns_cache_v2` gzip/protobuf 格式；Go 与 Rust 互读 fixture 见 [tests/fixtures](../tests/fixtures)。启动加载 dump 失败会记录错误并继续，正常关闭和 `dump_interval` 周期会保存。旧 Go writer 未保存 `msg_stored_time` 时的导入行为、Rust writer 的修正及调度差异见 [MIGRATION.md](MIGRATION.md#已知差异与修正)。

配置 `api.http` 后可访问：

| 请求 | 作用 |
| --- | --- |
| `GET /health` | 进程 API 可响应 |
| `GET /metrics` | cache、forward、显式 `metrics_collector` 与平台 process 指标 |
| `GET` 或 `POST /plugins/<tag>/flush` | 清空指定 cache |
| `GET /plugins/<tag>/dump` | 下载 Go v2 格式 dump |
| `POST /plugins/<tag>/load_dump` | 导入 dump，HTTP body 上限 16 MiB |
| `GET /plugins/<reverse_lookup_tag>/?ip=<address>` | 查询 reverse_lookup 保存的域名，未命中返回空文本 |

cache 的四族 `mosdns_cache_*`、显式 collector 的四族 `mosdns_metrics_collector_*` 均输出 Go 的 HELP/TYPE，同名 family 合并声明；共享 fixture 固定类型、help、标签转义和 collector 逐次整数毫秒统计。forward 的六族 `mosdns_forward_*` 保留 Go 名称、类型、`tag/upstream` 标签和 latency buckets，仅导出有 upstream tag 的实例；tag quick 配置共用计数。公开 `Options.event_observer` 可观察 exchange success/error/cancel 与连接生命周期；内部 retry/TC/bootstrap 不额外计为外部查询。传统 DNS/TLS/DoH 每个物理连接计一对 open/close，DoQ/H3 沿用 Go 不报告连接事件。Go 的 DoT 双重包装会计两对，而 Rust 计一对；Go 普通 DoH Close 不关闭 idle HTTP 连接，Rust 的显式 Close 会停止 driver 并释放池。

默认 process 指标不带 `mosdns_`，Go/Rust 共用 [名称/type fixture](../tests/fixtures/process_metrics.json)：Linux 提供 CPU、FD、virtual/resident memory、start time 和 namespace network octets；macOS 提供 CPU、FD 与 Mach memory，缺少 start time/network。无法读取的 sample 省略。Go runtime 指标和 pprof 尚未覆盖；`/health` 也不能证明上游或分流策略正常。API 当前没有认证机制，部署地址应按自己的既有访问边界配置。

## 测试

测试源文件保留 CLI、控制流、缓存、生命周期、TLS/HTTP/QUIC、Registry、共享 fixture 和 Linux 运行边界。GitHub 执行 fmt、full/minimal Clippy 与测试，并生成与正式 CLI 分离的 harness。按 [GitHub 构建与测试](../docs/github-workflow.md) 下载产物后，本机逐个运行相同 commit 的全部 native harness；Linux ARM64 harness 在指定目标设备独立运行。

TLS mock 证书和私钥不提交固定文件；GitHub Actions 在编译前临时生成原 include 路径的本轮素材，harness 内嵌一次性 localhost mock 输入。`generated_test_inputs` 单独记录路径、大小与 SHA，runtime-source 和 artifact 不打包生成私钥文件，公开测试证书可供运行验证；本地只运行已经校验的 harness，不重新生成或编译。

本机协议用例需要允许 loopback UDP/TCP；Linux packet info、abstract Unix namespace 和内核 set 用例需要相应平台。默认 ignored 的 `SO_MARK/SO_BINDTODEVICE`、nftset/ipset 等用例不计作通过，必须逐项明确执行并保存实际读回/清理记录。此前隔离测试验证过 nftset；IPSet 在历史目标上不受支持，真实元素互操作仍未验证，见 [内核实现来源与边界](src/pkg/kernel_sets/SOURCES.md)。

共享输入见 [tests/fixtures](../tests/fixtures)。默认测试不会更新 fixture。若要重新生成 Go/Rust cache dump 互操作输入，在外部 Go checkout 与 GitHub Rust 构建中分别设置显式导出路径，审核新文件后再同步：Go 使用 `MOSDNS_EXPORT_GO_DUMP`，Rust 使用 `MOSDNS_EXPORT_RUST_DUMP`。不能仅修改预期结果来消除差异。

## 目标架构与性能验证

GitHub 生成 macOS ARM64、Linux x86_64 musl、Linux ARM64 musl 的 full/minimal 产物。正式 CLI、harness、runtime-source 和 manifest 必须来自同一 commit；不同架构、profile 或 Cargo feature 合并结果不得混用。

后续实机目标为用户指定的 `192.168.100.131`。在独立 listener、任务目录和测试 nft 对象下运行全部回归，另测 CN site/CN IP 分流、mock/真实上游、hot/cold/disabled cache、UDP/TCP、并发与重复轮次。每轮保存二进制/规则/配置 SHA、boot ID、QPS、延迟、错误、RSS、体积和清理前后状态；响应正确与实际分流选择分别证明。性能配置的 disabled 模式若仅绕过 cache，不能据此认为进程没有 cache 对象或初始化成本。

迁移期的 128、131、122 历史验证/性能/失败报告保留在原 Go checkout 的 `deployments/`，2026-10-09 full/minimal 报告保留在其 `optimization/rust-profiles-20261009/`。这些私有运行证据没有复制到本仓库。旧结果只对应旧源码和产物，不能冒充本仓库新 commit 的完整验证；失败、重启中断与 partial pilot 也不能合并成完成的矩阵。
