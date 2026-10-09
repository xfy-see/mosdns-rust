# Rust 迁移进展与兼容边界

本项目遵循先复用并补充测试、保留相近模块和执行模型、再验证 CN site/CN IP 分流及性能的迁移顺序。Rust 已独立在 [xfy-see/mosdns-rust](https://github.com/xfy-see/mosdns-rust) 开发，[Go 实现](https://github.com/xfy-see/mosdns) 为外部行为与性能基线。下文记录 **full** 的接口与行为边界；minimal 的裁剪范围另见 [版本说明](../docs/rust-profiles.md)。

运行与 library API 见 [README.md](README.md)。编译在 GitHub 执行，本地下载产物后完整校验和运行，具体见 [GitHub 构建与测试](../docs/github-workflow.md)。迁移阶段优化保留模块与执行设计，减少 Engine future、请求复制与 TCP writer buffer 分配；默认 release 使用 fat LTO、单 codegen unit 和 strip，仍保留 panic unwind、完整协议与系统 CA。任何历史测试或性能数字都不证明新的 commit 已完成设备验证。

## 目录与接口映射

| 原 Go 位置 | Rust 位置 | 迁移方式与当前边界 |
| --- | --- | --- |
| `coremain/config.go`、`run.go` 的配置读取 | `src/coremain/config.rs`、`src/tools.rs` | 保留 `log/include/plugins/api`，YAML/JSON/TOML 按扩展名读取，include 先加载，深度上限 8，路径继续按工作目录解析；serde 拒绝未知字段 |
| `coremain/mosdns.go`、`plugin.go` | `src/coremain/engine.rs` | 构建 tag 到 plugin 的映射，校验依赖和循环，提供 `Engine::new/handle/handle_with_meta`；内建保留静态 enum dispatch，另有公开实例级 Registry 与扩展 traits |
| `pkg/query_context/context.go`、`kv.go` | `src/pkg/query_context.rs` | 保留 query/response、独立 client/upstream/response EDNS、marks、查询 ID 与时间；`client_valid` 区分 Unix 无 IP 客户端；已有 `reg_key` 和 lazy KV map，复制 map 但共享 `Arc` value；旧 `plugin/query_context` 仅 re-export |
| `coremain/plugin.go`、sequence `quick_setup.go` 与 `iface.go` | `src/coremain/registry.rs`、Engine 初始化/执行接点 | 实例级 Registry、工厂与引用、自定义 exec/matcher、多能力 PluginObject；BP logger/API/metrics、初始化登记回滚与动态 domain/IP provider 已有公开接口及回归 |
| `pkg/safe_close`、`Mosdns` 的关闭管理 | `src/coremain/lifecycle.rs` 与 Engine | 显式共享关闭信号、查询和后台任务 drain、幂等 closer、初始化失败回滚；Drop 不执行关闭钩子 |
| `plugin/executable/sequence/{config,chain,built_in}.go` | `src/plugin/sequence.rs`、Engine chain walker | 保留 rule 匹配与 continuation/jump-back；quick syntax 在构建时编译 |
| `pkg/matcher/domain`、`netlist` | `src/pkg/matcher/{domain,netlist}.rs` | 反向 label trie、full/regexp/keyword 与 IPv4/IPv6 prefix 匹配；共用 Go fixture |
| `plugin/data_provider` | Engine builder 中的 domain/IP providers | 保留 `exps/ips/files/sets` 与 matcher groups；暂未拆成逐 plugin 模块 |
| `plugin/matcher/*`、`plugin/executable/rate_limiter` | `src/plugin/matcher/mod.rs`、`rate_limiter.rs` | 保留 matcher 类型；domain/IP 实际数据结构留在 `pkg/matcher` |
| `plugin/executable/forward`、`pkg/upstream` | `src/plugin/executable/forward.rs`、`src/pkg/upstream/*` | forward 选择与并发仍在 Engine，指标与 observer 独立；传统 DNS、HTTPS、QUIC 分开实现 |
| `plugin/executable/cache`、`pkg/cache`、`pkg/concurrent_map` | `src/plugin/executable/cache.rs`、`cache/dump.rs`、`src/pkg/{cache,concurrent_map}.rs` | DNS cache 与 Go v2 dump；原 64 分片、per-shard capacity 和任意淘汰后端，亦用于 reverse lookup 与 selector |
| `hosts`、`redirect`、`arbitrary` | executable 类型、Engine、`executable/arbitrary/{zone,rdata,generate}.rs` | 按规则生成响应或包装 continuation；arbitrary 独立 lexer、header/directive 与 RData encoder，保留原 `parse_zone` 接口 |
| `ecs_handler`、`forward_edns0opt`、`dual_selector`、`reverse_lookup`、metrics | `src/plugin/executable/stateful.rs` 及 Engine | 保留状态、引用查询和完成后处理；暂集中在一个模块 |
| `plugin/server/*`、`pkg/server`、`pkg/server_handler` | `src/pkg/server/{mod,socket,udp,tls,http,quic}.rs` | listener 与 framing 独立，Engine 处理查询；保留配置类型名称和 TLS/SNI/path metadata、Unix stream 和 Linux UDP packet info |
| `plugin/executable/{ipset,nftset}`、`pkg/nftset_utils` | `src/plugin/executable/kernel_sets.rs`、`src/pkg/kernel_sets/*` | 保留 quick syntax；原生 NETLINK_NETFILTER、已有 set 添加、ACK/错误与 nft interval 编码，无外部 CLI |
| `coremain` HTTP API | `src/api.rs`、`src/pkg/metrics.rs` | cache、reverse lookup、metrics 与 health；forward 六族与 Linux/macOS process collector；Go runtime/pprof 未迁移 |
| `main.go`、`coremain/run.go`、`service.go` | `src/main.rs`、`src/service.rs` | 独立 `mosdns-rs` CLI；CPU worker、Unix as-service、systemd/launchd/procd 定义与操作；Windows 原生 SCM dispatcher/manager 代码已通过交叉检查，实际 SCM 未验证 |
| `tools` 配置与连接 probe | `src/tools.rs`、`tools_tests.rs` | `config gen/conv` 与 TCP/TLS `probe idle-timeout/conn-reuse/pipeline`；输出不覆盖，idle 有明确观察上限 |

`src/lib.rs` 导出 `coremain`、`pkg`、`plugin`、`api` 和 `tools`。`Config::load(&Path)` 解析 include；测试或嵌入式调用可用 `Config::from_yaml`，但 `Engine::new` 不自行读取尚未解析的 include。服务管理模块属于 binary CLI。

`Engine::servers()` 提供 listener 描述；`handle(query, client, entry)` 处理单问题 query，`handle_with_meta` 另接收 HTTP path 和 TLS server name。`handle_with_client_meta` 接受 `Option<IpAddr>`，用于 Unix 无 IP 客户端。Engine 产生错误由 listener 转成 SERVFAIL，成功结束但无 response 时产生 REFUSED。listener 设置 RA，并按客户端 EDNS/UDP 大小处理响应，总 query deadline 为 5 秒。

## 当前覆盖

| Go 功能 | Rust 当前状态 | 主要参数与约束 |
| --- | --- | --- |
| `domain_set` / `ip_set` | 已实现 | `exps` / `ips`、`files`、组合 `sets`；文件读取错误导致初始化失败 |
| `sequence` | 已实现 | `matches` 的 AND/取反、inline 和 `$tag`；支持 scalar `matches` 与列表 |
| 内建控制流 | 已实现 | `jump/goto/return/accept/reject`，reject 默认为 RCODE 5 |
| domain/IP matchers | 已实现 | `qname/cname/client_ip/resp_ip/ptr_ip`，内联、`$set`、`&file` |
| 其余 matchers | 已实现 | `qtype/qclass/rcode/has_resp/has_wanted_ans/mark/env/random/string_exp/_true/_false` |
| `forward` | 已实现连接选项 | `upstreams/tag/addr/concurrent`、tag quick configure 子集；`dial_addr/idle_timeout/enable_pipeline/enable_http3/insecure_skip_verify/socks5/bootstrap/bootstrap_version/so_mark/bind_to_device`，保留 global defaults |
| `fallback` | 已实现 | `primary/secondary/threshold/always_standby`，clone query context，分支最多执行 5 秒 |
| `cache` | 已实现 | `size/lazy_cache_ttl/dump_file/dump_interval`；TTL 衰减、负缓存、递归写回、lazy 去重和跨语言 dump |
| `hosts` / `redirect` / `arbitrary` | 已实现常用规则 | entries/rules/files；hosts/redirect 无前缀规则默认为 full；zone 默认 TTL 3600、保留显式 SOA TTL |
| `ttl` / `black_hole` / `drop_resp` / `sleep` / `mark` | 已实现 | 固定/区间 TTL、A/AAAA、删除 response、毫秒 sleep 和 marks；含 `_sleep_500ms` preset |
| `ecs_handler` / 旧 `ecs` | 已实现 | `forward/send/preset/mask4/mask6`；旧 quick syntax 只取首地址，默认 mask 24/48 |
| `forward_edns0opt` | 已实现 | 指定 option codes 的请求/响应转发；与 Go 相同在 continuation 完成后处理 upstream option |
| `prefer_ipv4` / `prefer_ipv6` | 已实现 | 并行参考查询，原查询完成后最多额外等 500ms，preferred-type knowledge 缓存 1 小时 |
| `reverse_lookup` | 查询与 HTTP lookup 已实现 | `size/handle_ptr/ttl`；Engine 提供 `reverse_lookup(tag, ip)` 方法，API 使用 `/plugins/<tag>/?ip=...` |
| `rate_limiter` | 已实现 matcher | `qps/burst/mask4/mask6`；真实子网聚合是明确的 Go bug 修正，见下表 |
| `metrics_collector` / query 日志 | 已实现基础部分 | collector queries/errors/active/latency histogram；summary/debug 使用当前 logger 配置；未等同完整 zap/runtime metrics |
| CLI 与工具 | 已实现运行入口和常用工具 | `start/check/version`、CPU worker、Unix as-service、`config gen/conv`、TCP/TLS probe、service 模板及操作；service 真实 lifecycle 仍未验证 |
| UDP/TCP/DoT/DoH/DoQ upstream | 已实现 | persistent session、private ID namespace、TC fallback、TLS 校验、DoH HTTP/1.1/2/3、MIME/status/size、DoQ ID/framing |
| UDP/TCP/TLS/HTTP/HTTPS/QUIC listener | 已实现 | `udp_server/tcp_server/http_server/quic_server`；HTTP entries、source IP header、SNI/path metadata；TLS 使用 PEM 文件；TCP/HTTP 支持 Unix |
| `nftset` | Linux 原生实现，131 隔离内核用例通过 | quick syntax 与 Go mask defaults、已有 set 默认 timeout；验证 IPv4/IPv6、interval 与 timeout readback；非 Linux 初始化报错 |
| `ipset` | Linux 原生代码与 wire 测试已有，真实添加未验证 | 131 protocol-only 查询返回 EINVAL，未找到目标 IPSet 模块支持；需支持 IPSet 的隔离内核继续验证 |

部分 Go 名称只注册为 sequence quick syntax，部分注册为独立 plugin。Rust builder 也提供了少量额外的具名 matcher 入口；覆盖表描述可执行能力，不能据此推断两语言的注册 API 完全相同。

未知 plugin/matcher/executable 会明确报错。Go 中已经无效的 `max_conns` 继续可解析且不影响连接数；对某些没有 quick-configure 接口的 `$tag`，多余 quick args 沿用 Go 的忽略行为。

## 保留的执行语义

`jump` 把调用方剩余链作为 jump-back，子链到末尾或 `return` 后继续调用方。`goto` 丢弃原有 jump-back；`accept` 和 `reject` 停止当前递归 continuation。普通 `$sequence` 是独立 executable 调用，内部 `accept` 只结束该调用，返回后调用方继续。这些区别有 Go 原 case 和独立 review 回归测试。

cache 命中只把缓存 response 放入 query context，仍执行后续规则。continuation 完成后才写回；命中 response 仅被 TTL 修改时不会重新启动缓存寿命。lazy refresh 在安装 cached response 之前复制 context，因此不会被后续 `has_resp` 提前截断，且同 key 刷新去重。

forward 的 `concurrent` 最多为 3，从随机起始位置选择 upstream；配置 upstream 数量不足时可能重复选同一个。NOERROR 和 NXDOMAIN 是可立即接受的响应，包括 empty NOERROR。其它 RCODE 在尚有结果时继续等待，最后一个结果可返回其 RCODE。`fallback` 判断分支执行成功且有 response，不把某个 DNS RCODE 自动当作分支失败。

query context 总是给 upstream query 换成新的 EDNS OPT，payload 为 1200，默认不继承客户端 option 或 DO。response 单独保留客户端 DO，upstream OPT 不直接泄漏给客户端；只有显式 ECS/EDNS 插件按需复制 option。即便 cache 命中，最终 OPT 也根据当前客户端重建。

## 已知差异与修正

这些行为是迁移时需要单独审查的兼容边界。已有 fixture 不代表所有异常输入、DNS record 类型、系统限制或配置扩展均已证明等价。

| 项目 | 迁移时 Go 基线行为 | Rust 当前行为 / 影响 |
| --- | --- | --- |
| `env KEY VALUE` | quick setup 将 key 第二次赋值为 VALUE，实际检查错误的变量名 | 按 KEY 的值是否等于 VALUE 判断；在构建时求值，与 intended API 一致，但修正了原行为 |
| 限流 mask | `Prefix(mask).Addr()` 未调用 Masked，实际未按 mask 聚合 | 对 masked IPv4/IPv6 地址聚合 token bucket；同网段客户端在配置 mask 后会共享限额 |
| cache key | 不含 qclass，qtype 高 byte 写成 `byte(qtype << 8)`，恒为 0 | 内存 key 包含 qclass 和完整 qtype，避免 class/大 qtype collision；标准 IN A/AAAA fixture 不受影响 |
| cache dump key | 使用上面的历史 byte layout | 导出保持历史 layout，导入从 DNS question 恢复完整 qtype/class；Go 读者仍有历史 key 限制 |
| dump stored timestamp | writer 未填 `msg_stored_time`，旧 dump reload 后 TTL 通常降到 1 | 导入旧 Go dump保留该行为；Rust writer 填真实 timestamp，Go/Rust 读者可正确计算余下 TTL |
| 缓存后端 | 64 shard `concurrent_map`，容量满时按 Go map 迭代顺序任意淘汰，默认容量 1024，周期清理 expired entries | 同样的分片容量与周期 GC；随机 hash/map 迭代顺序不同，不逐项复刻淘汰对象。Rust Flush 使用写锁，过期读者删除前核对 entry identity，避免 Go 的共享锁 mutation 与删除新 entry 竞态 |
| periodic dump | 一个周期内至少 1024 次更改才写出 | 每个 `dump_interval` 都写；未复用 Go 的 updated-key 门槛；大 cache 的写盘开销需单独测量 |
| forward 落后请求 | winner 返回后，已启动请求在独立 context 中继续最多 5 秒 | 同样以 tracked Tokio task 在独立 5 秒 deadline 中继续；赢家与 caller 取消只释放前台 receiver，shutdown 排空后关闭 transport |
| fallback 落后分支 | 已启动分支继续运行，可能填自己的 cache | 同样以独立 Tokio task 继续，branch deadline 为 5 秒 |
| TCP/TLS 复用 | 根据 reuse/pipeline 选项选择 transport | `enable_pipeline: false` 使用每连接一个查询的空闲连接池，忙时另建连接；取消/错误关闭独占连接，idle 主动清理；旧连接失败按 Go 的限定重试代码执行，新连接失败立即返回 |
| pipeline 资源模型 | 可扩展连接，TCP/TLS 每连接 64 in-flight，UDP 4096 | 连接池可扩容，TCP/TLS 每连接 64、UDP 4096 in-flight；Rust 扫描 Vec，Go map 的随机/最多 17 次失败 reserve 迭代不逐次复刻；Rust 的拨号归等待者 future，取消启动者会中止拨号，其它等待者可重拨，最后等待者取消立即删 slot，Go 背景拨号继续至 5 秒上限或 idle。旧连接在 EOF/idle 关闭竞争中失败时，当前查询最多重试两次；新连接失败或活连接上的 DNS 验证错误直接返回。总 deadline 不因重试延长 |
| traditional waiting-reply 健康检查 | pipeline 等待 reply 时读健康 deadline 10 秒，独占复用 query 上限 6 秒 | Rust 分别采用相同的 10/6 秒限制，pipeline 任意 reply 恢复 idle deadline；整次 Upstream deadline 独立保留 |
| malformed DNS | Go 对基础 query 校验失败不返回 payload | Rust 对可构造响应的错误请求返回 FORMERR；短于 DNS ID 的 payload 仍可能被忽略 |
| regex | Go RE2/string normalization | Rust regex 并翻译部分 Go 字符类/ASCII shorthand；共享 fixture覆盖当前已知差异，不能认为全部 RE2 syntax 完全一致 |
| 日志 | zap 格式、字段和级别 | logger 接受现有 level/file/production；query 和 BP named logger 支持 JSON/文本与共享文件锁，没有 zap 的 fatal/panic、采样及逐字段格式复刻 |
| `--cpu` | 设置 GOMAXPROCS | 设置 Tokio worker_threads；不是 CPU affinity，blocking task 使用独立线程，资源模型不完全等价 |
| service 名称与安装 | 默认名称 `mosdns`，由 kardianos/service 处理各平台 | 默认 `mosdns-rs`，原生 systemd/launchd/procd/Windows SCM；文件 create_new 或 SCM create 不覆盖，管理命令检查工具标记，未实际安装验证 |

Go 的每 shard 容量为 `size / 64`，总容量上限按 64 的倍数向下取整；当 `0 < size < 64` 时 shard max 为 0，实际不执行容量淘汰。`pkg/cache` 注释写的 minimum 1024 没有相同的运行时钳制，非正数在 DNS cache 参数初始化时才采用默认 1024。Rust 通过共享容量 fixture 保留这一边界，见 `tests/fixtures/cache_backend.json`。cleaner 在 Tokio runtime 中启动；同步 library 构造后，首次 get/store 在 runtime 内会补启动。未进入 runtime 的同步 library 使用仍可主动 gc/lookup。关闭仅停止自动清理，显式 cache 操作保持可用，与 Go Close 相同。

hosts/redirect 初期移植的“最后匹配行优先”已经修正为 Go 的 full、最长 domain、regexp、keyword 优先级。同一 normalized domain 的后写覆盖、空类型前缀按 full 处理和 Unicode 归一已补独立 `review_regressions`；这些是值匹配规则，布尔 domain-set 测试不能单独证明它们正确。

Go `include` 依照文件出现顺序初始化 plugin，通常要求引用先定义。Rust 会解析完整依赖图，允许后定义引用，并明确拒绝 dependency cycle。Go 的随机 anonymous tag 在 Rust 中改成确定性的 `__anonymous_<index>`，不能依赖该实现内部名称作为公共 tag。

Go `RegKey` 的唯一非零 key 和 QueryContext KV 已有 Rust 对应。值类型要求 `Any + Send + Sync`，以适配 Rust async/background 查询；Go 的 `any` 本身没有这种编译期约束。`clone` 复制 KV map 而不深拷贝 value；独立查询不共享 KV。Rust key overflow 会 panic 并保留终止值，避免 panic 被捕获后再次注册产生旧 key。Go/Rust 对照测试覆盖 map 覆盖/删除独立、value 共享、factory 注册和初始化错误；Rust 另测并发 key 注册、递归链、取反错误和 AND short circuit。

Rust Registry 显式传给 `Engine::new_with_registry`，可 clone、查询和删除自定义注册；没有隐式 Go `init()` 全局表。内建类型保留静态实现，不允许删除或替换，`get_*` factory lookup 只返回扩展工厂，`*_types` 列表同时包含内建名称。初始化工厂接收 YAML Value，自行选择 serde 解码和参数检查，未自动复刻 Go 对所有自定义 Args 的 WeakDecode。preset tag 与配置 tag 冲突明确失败；自定义数据可由 `Plugin::Data` 保存并在 build/runtime 查找。tagged 自定义 exec/matcher 的 quick configure、异步 matcher 错误、递归 tail 与终止链均有 [public API 回归](tests/plugin_registry.rs)。内建 matcher 仍使用无 heap allocation 的同步匹配分支。

arbitrary 的 [zone fixture](../tests/fixtures/zone_records.json) 固定 owner wire、type/class/TTL 与无压缩 RData wire：225 个成功案例含 248 条 RR，85 个拒绝案例，涵盖 DNSSEC、TLSA/SMIMEA、DNAME/RP/URI/CAA、LOC、ILNP/EUI、APL/HIP/IPSECKEY、SVCB/HTTPS 与未知数字类型。`$GENERATE` 支持 Go 的 d/o/x/X 修饰符和子 parser TTL/owner 行为，不宣称 BIND n/N 扩展。Go miekg/dns 1.1.72 的 AMTRELAY 在 discovery 位为 1 时，parser 接受 gateway、writer 却未掩去该位，导致 wire 网关丢失；Rust 保留完整 gateway。Go 诊断和 Rust 独立回归明确记录这一修正，不把这个案例算作相同 wire。

## 尚未迁移或限制明确的功能

| 缺口 | 当前处理 | 下一步 |
| --- | --- | --- |
| Linux kernel 与 socket options 的完整实机矩阵 | 131 上 nftset 两项和 SO_MARK/SO_BINDTODEVICE 已通过；ipset protocol-only 失败且真实添加未验证；非 Linux 明确拒绝 | 换支持 IPSet 的隔离内核补添加、timeout 和错误用例；继续扩展不同 kernel/set 类型与权限/lifecycle 矩阵 |
| service 平台与实际 lifecycle | systemd/launchd/procd 模板与原生 Windows SCM 已实现；Windows 仅交叉检查和状态模型测试；FreeBSD/Solaris/AIX、Linux SysV/Upstart/OpenRC/rcS 及 user-service 模式未实现 | 在独立测试实例验证安装、开机、信号关闭与卸载；本次只测代码与生成，不自动注册 production 服务 |
| 自定义插件的完整 BP/Mosdns contract | Registry、KV、多能力 object、生命周期、动态 provider、named logger、API mount 和 typed metrics 已有，并验证失败序列/quick panic 回滚；没有完整 zap/Prometheus client API | 扩展 summary/vector 与日志高级接口按真实使用需求实现；保持静态 matcher 分支 |
| 完整 API/metrics | cache、reverse lookup、forward 六族、显式 collector 和 Linux/macOS process 指标可用；Go runtime/pprof 未移植 | Go runtime 指标不能直接等同 Rust runtime；Rust profiler 接口需另行设计 |
| TLS trust 平台细节 | 所有 TLS client 使用系统 roots；Linux 文件/目录及独立环境覆盖规则对齐 Go，macOS 导入系统 roots 给 rustls；没有 YAML CA 参数 | macOS SecTrust 的策略校验与 Windows trust 行为仍需进一步验证 |
| arbitrary DNS record / zone syntax 的格式边界 | 310 个共享案例覆盖 Go 全部 80 个 TypeToRR constructor、89 数字类型，以及 $GENERATE/RFC3597；$INCLUDE 仍依 Go caller 禁用 | 未穷尽畸形 RFC3597、EDNS option 内部字段与奇异非 UTF-8 generate 转义；未知数字类型保留 opaque octets，不检查私有格式 |

DoH dial override 保留原 TLS identity/HTTP Host；IP URL、SOCKS5 或 Linux socket controls 使用独立 Hyper transport，普通 DoH 使用 reqwest。UDP、其 TC 后的 TCP fallback、QUIC 和 HTTP/3 与 Go 相同绕过 SOCKS5；SOCKS5 只提供无认证 CONNECT。bootstrap 使用指定 DNS 与 address family，支持 TTL 缓存和去重更新。普通 UDP upstream 每秒在同一 socket、同一 ID 重传，收到应答、超时或取消后停止；`tcp+pipeline`/`tls+pipeline` 强制 pipeline，普通 TCP/TLS 遵循选项；UDP TC→TCP fallback 使用 direct reuse 和独立的 10 秒 idle timeout，不继承显式 UDP 参数。Rust 仍接受 UDP 的显式 idle timeout，而 Go 的 UDP socket 固定为 5 分钟。`doq://` 与 `quic://` 等价；DoH 保留原 URL path，包括 `/`。丢首包、取消、非 pipeline 并发/复用/过期/旧连接重试，以及 bootstrap 取消和失败恢复已有独立回归。pipeline 每次拨号上限 5 秒，UDP 重传不重新修改等待/idle deadline；另覆盖 TCP/TLS 旧连接 EOF、已选 session 的 idle 关闭竞争、新连接失败不重试、活连接 DNS 校验错误与取消重试后的资源释放。lazy refresh 的尾链超时释放 key 后能再次刷新也已覆盖。

当前 cache API 指标使用 `mosdns_cache_query_total/mosdns_cache_hit_total/mosdns_cache_lazy_hit_total/mosdns_cache_size_current`，显式 collector 使用 `mosdns_metrics_collector_*`。两者分别通过 [cache fixture](../tests/fixtures/cache_metrics.json) 和 [collector fixture](../tests/fixtures/metrics_collector.json) 验证 HELP/TYPE、同 family 合并和标签转义；collector 按 Go 的逐次整数毫秒累计响应延迟。forward 的六族名称、type、标签和 buckets 由 [共享 descriptor fixture](../tests/fixtures/forward_metrics.json) 固定；仅 tagged upstream 导出。公开 optional observer None 保留普通 DoH 的 reqwest 路径，Some 使用 Hyper 以观察物理连接；整次 exchange 计一次 query，内部 retry/TC/bootstrap 不重复计。DoT 计物理 socket 一对事件，Go 的 raw/TLS 双 wrap 计两对；DoQ/H3 均没有 connection events。Go 普通 DoH Close 不执行 CloseIdleConnections，Rust 显式 close 会停止 HTTP driver 并释放池，这是生命周期修正。Rust 在完整 DNS 校验后报告 Success，Go 在 Forward Unpack 前报告，malformed upstream payload 的细粒度指标可能不同。

默认 process 指标不带 `mosdns_` 前缀；Go/Rust 共用 [名称/type fixture](../tests/fixtures/process_metrics.json)。Linux 提供 CPU、FD、virtual/resident memory、start time 与 procfs network octets，network counters 是进程所在网络 namespace 的统计，与 Go collector 相同，并非单进程或单上游字节计数。macOS 使用 getrusage/getrlimit 和 Mach memory，暂不提供 start time/network；无法采集的 sample 省略。Go runtime 与 pprof 未迁移。

系统 CA 是每进程的快照，所有 TLS upstream 和 probe 共用。有效 roots 与坏项并存时保留有效项并报告坏项；没有可用 roots 时返回初始化错误，insecure 模式绕过 CA 加载。Linux 使用 Go 1.26.0 的默认 CA paths 和两个非空环境变量的独立覆盖规则；macOS 使用 rustls-native-certs 导出的 roots，不能当作 Go SecTrust 策略完全等价。私有 CA 集成测试在子进程中设置环境，未修改系统 trust store。

Engine 的显式 shutdown 共享于所有 clone，拒绝新查询后等待活跃查询、后台 tail、周期 dump 和 attached service，再保存 cache dump 和关闭资源；初始化失败会回滚登记的部分资源。每次 Engine 初始化/关闭按 Arc identity 去重，采用逆初始化顺序，Go 是无序 plugin map；Drop 不执行 closer。工厂必须在取得资源后及时 `register_closer(...)?`，service 必须响应关闭信号并结束，才能进入最终 closer。已回滚关闭的 Arc 再注册明确报错。不同 Engine 共享同一 Arc 的全局关闭语义由扩展负责。启动回滚同步执行，正常 shutdown 的 closer 在 blocking worker 执行；关闭错误或 panic 聚合，取消 waiter 不取消关闭协调任务。见 [生命周期测试](tests/plugin_lifecycle.rs)。

Rust listener 对并发、连接、首包读取、body size 和待处理 ID 设置上限；这些资源限制没有完全复刻 Go。UDP/TCP listener 请求 `SO_REUSEPORT` 和 64 KiB 接收缓存，QUIC 使用 Quinn 自己的 endpoint，不能把前两种 listener 的 socket option 测试推广到全部协议。

## 验证与后续顺序

行为基线保留为两语言共享的 domain/netlist/split/cache dump/指标/zone fixture。Rust 回归覆盖 control flow、cache lifetime、lazy/fallback 背景执行、EDNS 隔离、connection reuse/cancellation、TLS/HTTP/QUIC、公开 Registry 与生命周期。默认测试不会改写 fixture；修改 fixture 需在外部 Go 基线与 Rust 中同步解释和验证。

后续按 [GitHub 构建与测试](../docs/github-workflow.md) 完成：

1. 先增加能复现问题的测试，再修改实现，保留 full/minimal 与迁移兼容边界。
2. 本地静态检查并 push，GitHub 编译、质量检查和测试，生成绑定精确 commit 的正式 CLI 与 harness。
3. 下载校验摘要与源文件快照，本机完整运行匹配架构的 full/minimal harness 和 CLI 回归。
4. 在用户指定的 `192.168.100.131` 完成 Linux ARM64 回归、socket controls、nftset 独立读回及完整性能矩阵；IPSet 需要支持对应 subsystem/type 的目标，不能以 nftset 通过代替。
5. 比较 mock 分流与真实上游，分别报告 hot/cold/disabled、UDP/TCP、并发、重复轮次、错误和延迟；配置全覆盖、真实流量和回滚步骤成立后再评估具体生产替换。

service lifecycle、实际 Windows SCM、语言相关 observability 与 IPSet 元素互操作保持前文明确的验证限制。普通 CI、默认 ignored 未执行、交叉编译或部分 pilot 不能当作这些平台行为已验证。disabled cache 若只是 sequence 绕过 cache，仍含初始化与对象成本。

2026-10-07 的分批兼容/优化测试、128/131 性能与失败记录保留在原 Go checkout 的 `deployments/`；2026-10-09 full/minimal 记录保留在其 `optimization/rust-profiles-20261009/`。本独立仓库不复制这些部署数据。历史报告绑定各自源码、二进制、采样器与目标状态；新 commit 必须建立新证据目录，保留失败和中断的原始状态，不能改写旧结果或将不同轮次合并为完整验证。
