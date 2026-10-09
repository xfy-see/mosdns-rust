# GitHub 编译、下载与完整验证

本仓库使用本地编辑、GitHub 编译、下载后测试的流程。本地不需要 Rust/Cargo，不安装工具链或构建依赖；运行已经下载并验证的 Rust CLI 和 test harness 不需要 Cargo。

## 1. 本地修改与提交

先复用或补充能复现问题的测试，保留 `rust/` 结构与共享 `tests/fixtures/`。检查源码和暂存内容，不把本地产物、设备配置或历史报告提交：

```sh
git status --short
git diff --check
git diff
git diff --cached
```

Python/JSON/YAML 和 shell 辅助工具可在本地做静态检查；Rust fmt、Clippy、编译与 Cargo 测试都交给 CI。终端 Git 已配置可用认证时，提交本任务文件后 push 到本仓库当前分支，记录完整 commit：

```sh
git push origin HEAD
commit=$(git rev-parse HEAD)
source_root="$PWD"
```

终端 Git 缺少认证时，可用用户已授权的 GitHub connector 发布审核后的本地源码 tree，不把 token 或私钥写进仓库。连接器返回的远端 commit SHA 可能与本地 commit 不同，必须以实际远端完整 SHA 为准；不能用本地 SHA 代替。保留原开发 checkout 的提交与修改，为远端 commit 创建新的干净 checkout 后再验证，例如：

```sh
published_commit=REMOTE_FULL_COMMIT_SHA
git fetch origin "$published_commit"
git worktree add --detach /absolute/new-clean-checkout "$published_commit"
cd /absolute/new-clean-checkout
commit=$(git rev-parse HEAD)
source_root="$PWD"
```

`REMOTE_FULL_COMMIT_SHA` 替换为连接器实际返回的完整 SHA；公开仓库的 fetch 不需要恢复写入凭据。新的 checkout 仅用于下载与验证，后续开发仍在原开发 checkout。需要运行校验的 commit 必须已发布且源码与该 SHA 一致；未提交的改动不能当作该构建的来源。

下载校验和设备控制器使用已有 Python 3.10+。先选择现有解释器并检查版本，后续命令统一使用它；不安装 Rust 或 Python，也不依赖 macOS 默认 `python3` 的版本：

```sh
PYTHON=/absolute/path/to/existing/python3
"$PYTHON" -B -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"; print(sys.executable, sys.version)'
```

## 2. 等待同一 commit 的 GitHub run

[build.yml](../.github/workflows/build.yml) 在 push、pull request 和手动触发时运行。它包含 fmt、full/minimal Clippy、Windows 双版本检查/测试，以及下列可下载产物：

| target | profile | GitHub runner |
| --- | --- | --- |
| `aarch64-apple-darwin` | full / minimal | macOS ARM64 |
| `x86_64-unknown-linux-musl` | full / minimal | Linux x86_64 |
| `aarch64-unknown-linux-musl` | full / minimal | Linux ARM64 |

CI 固定工具链版本，用 Cargo.lock/`--locked` 锁定依赖。正式 CLI 与 harness 分别构建和记录，质量检查和 Windows 测试不冒充设备运行。工作流不自动安装生产服务，也不发布 GitHub Release。

TLS 测试证书和临时私钥由 CI 使用 OpenSSL 在原 fixture 路径生成，Rust 测试实现及 `include_bytes!` 路径保持原样。仓库不提交固定测试私钥，artifact 不打包私钥 DER/PEM 文件；新私钥仅用于编译测试 harness，编译后删除。四份公开证书可随冻结快照保留。manifest 的 `source_inputs` 只覆盖 Git tracked 文件，`generated_test_inputs` 单列本次生成 fixture 的类型、大小、摘要与是否打包，`generated_test_tree_sha256` 绑定整组生成记录。因此不同 run 的测试证书、harness SHA 可能不同，仍需绑定实际 run 与本次产物。

使用 GitHub UI 或已登录的 `gh` 查看对应完整 commit 的 run：

```sh
gh run list --repo xfy-see/mosdns-rust --workflow build.yml \
  --commit "$commit" --json databaseId,headSha,status,conclusion
```

选取 `headSha` 与 `$commit` 完全相同的 run，记录 run ID，再等待结果；以下 `run_id` 使用实际值：

```sh
run_id=123456789
gh run watch "$run_id" --repo xfy-see/mosdns-rust --exit-status
gh run view "$run_id" --repo xfy-see/mosdns-rust \
  --json headSha,status,conclusion,url
```

失败时保留日志，修复并提交新 commit。不能从其它 commit 借成功 binary 来测试当前改动。下载与 SHA 校验必须绑定可信 GitHub run；manifest 自己不能证明构建来源或代码正确。

## 3. 下载并校验 native 产物

artifact 名为 `mosdns-rs-<target>-<profile>-<完整commit SHA>`。每份包含正式 `bin/mosdns-rs`、harness、`runtime-source/`、manifest、构建与测试日志、普通/ignored 测试列表。Linux musl binary 可直接在匹配 CPU 架构的设备上运行；不同 target/profile 不能混用。

以下在 macOS ARM64 开发机上下载 full。下载目录和结果目录均使用新的唯一名称；现有证据目录不可覆盖：

```sh
gh run download "$run_id" --repo xfy-see/mosdns-rust \
  --name "mosdns-rs-aarch64-apple-darwin-full-$commit" \
  --dir /absolute/new-download/native-full

"$PYTHON" -B ci/download-and-test.py \
  --artifact /absolute/new-download/native-full \
  --expected-commit "$commit" \
  --expected-target aarch64-apple-darwin --expected-profile full \
  --source-root "$source_root" \
  --output /absolute/new-results/native-full
```

minimal 使用自己的 artifact、`--expected-profile minimal` 和新的输出目录再完整执行。`--artifact` 也支持直接下载的 ZIP；工具会检查路径安全与完整文件集合，不接受 manifest 外额外文件。Python 需要 3.10+。

验证器检查 commit/target/profile、文件大小与 SHA-256、冻结源码输入和完整清单。正式核验需要 `--source-root` 与当前 Git checkout 的 HEAD、完整 tracked 文件集合和逐文件摘要对照，未提交的源码修改会导致失败。它保留 artifact 副本，运行下载的正式 CLI 的 `version`、隔离配置 `check` 和全部普通 harness，默认串行。实际 `--list` 的普通/ignored 测试集合必须与 CI 清单一致，运行统计也必须匹配，防止漏测；执行时工作目录使用 artifact 的源码快照。

额外的冻结 fixture 只能来自 `generated_test_inputs` 中明确标为已打包的公开证书，内容必须符合证书容器；它们不混入 tracked 源码集合。下载验证器拒绝明文私钥文件、PEM 私钥内容和独立 DER 私钥，即使文件已列入 manifest 且摘要匹配；已生成的测试私钥可以内嵌在验证过的原生 harness 中。

`--output` 中的 `RESULT.json` 保存验证器与 manifest SHA、源码树摘要、文件校验、运行状态与结果；`logs/` 保存 stdout/stderr，`runtime-progress.json` 保存执行进度。验证或运行失败也保留该新目录。只有该目录记录的实际运行可作为本机验证；GitHub 的测试通过不能替代它。默认 ignored 逐项列出，不算通过。显式测试使用 `--run-ignored 'harnesses/<name>/<binary>::exact_test_name'`，要求恰好一个测试通过。full 的 `hot_cache_cpu_profile` 可以按清单中的准确 harness 路径单独运行；它只测无网络 CPU/分配，不代替吞吐矩阵。Linux 权限测试交给设备控制器逐项选择。

## 4. 下载 Linux ARM64 后在 131 完整测试

先下载同一 commit 的 ARM64 full，再做本地文件验证，不在 macOS 执行 Linux binary：

```sh
gh run download "$run_id" --repo xfy-see/mosdns-rust \
  --name "mosdns-rs-aarch64-unknown-linux-musl-full-$commit" \
  --dir /absolute/new-download/arm64-full

"$PYTHON" -B ci/download-and-test.py \
  --artifact /absolute/new-download/arm64-full \
  --expected-commit "$commit" \
  --expected-target aarch64-unknown-linux-musl --expected-profile full \
  --source-root "$source_root" --verify-only \
  --output /absolute/new-results/arm64-full-verified
```

minimal 同样下载并校验独立产物。`--verify-only` 只证明文件与清单相符，其结果不会记为测试已经运行。

使用 [test-router.py](../ci/test-router.py) 将已校验的 CLI 和 harness 串行发送到 `192.168.100.131` 的独占任务目录，每次上传后再次读回 SHA。该控制器核对架构、boot ID、内存、临时空间、静态配置摘要、53 端口监听和 nft 表，使用 [router-session.sh](../ci/router-session.sh) 的进程身份及超时守卫。源码快照留在本地作为校验输入；当前 harness 的 fixture 已嵌入 binary。

以下 SSH 参数使用本地已有的身份文件与已确认的主机密钥，不能关闭主机密钥检查。先读当前 boot ID，再创建新的 full 结果目录执行：

```sh
ssh_identity=/absolute/path/to/existing/ssh_identity
known_hosts=/absolute/path/to/confirmed/known_hosts
boot=$(ssh -i "$ssh_identity" -o BatchMode=yes -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" \
  root@192.168.100.131 'cat /proc/sys/kernel/random/boot_id')

"$PYTHON" -B ci/test-router.py \
  --artifact /absolute/new-results/arm64-full-verified/artifact \
  --source-root "$source_root" --expected-commit "$commit" --profile full \
  --host 192.168.100.131 --identity "$ssh_identity" \
  --known-hosts "$known_hosts" --expected-boot "$boot" \
  --output /absolute/new-results/router-full \
  --execute --nft --socket-options --ipset-probe
```

minimal 使用其验证目录、`--profile minimal` 和新的设备结果目录重跑。省略 `--execute` 只生成计划，不连接或运行设备测试。`--nft` 精确选择两个独立 nftset 用例；`--socket-options` 选择支持的 mark/接口绑定用例；`--ipset-probe` 运行只读 IPSet 能力探测并单列结果。IPSet 模块不支持时保留 `unavailable_or_failed` 和原始日志，不将其算作测试通过。其他 IPSet 写入用例仍逐项列为未运行；本机和设备普通测试通过都不能证明这些权限能力。

设备输出包括 `plan.json`、逐条 SSH 原始日志、`commands.jsonl` 和 `RESULT.json`。全部普通测试、选择的权限用例、清理状态和设备前后守卫分别记录；所有权进程仍存活或配置、DNS、nft 状态变化时不能判定成功。CN 分流与性能矩阵还需下一节的专门测试，不包含在该 harness 控制器中。

本仓库不存设备凭据和生产配置。已有 Go checkout 可作为外部 benchmark 控制器和冻结 Go baseline 的来源；远端控制器必须使用本次下载产物和冻结的 runtime-source，不能复用旧 Rust 编译输出。仅清理本次创建的进程、目录和唯一测试 set，保留原服务和路由。

## 5. 完整性能测试与结果

完整验证另需可复现 CN site/CN IP 策略与实际流量检查。固定本 commit 的 binary、Go 对照、规则与配置，覆盖 mock 分流选择、真实 DNS 响应、hot/cold/disabled cache、UDP/TCP、并发和重复轮次，报告 QPS、延迟、错误、RSS 与文件体积。query 响应正确不能单独证明 upstream 选择正确。

每轮记录 commit、run/artifact、CLI/harness/配置/列表 SHA、boot ID、计划、原始日志和前后清理状态。设备重启、SSH 中断或配置 guard 失败保留为原始失败，新目录重试；未跑完的矩阵只能报告实际覆盖。GitHub 编译成功、本机普通测试、设备回归、权限测试和性能结果分别给出结论。

下载产物与原始本地/设备报告放仓库外或已忽略的 `.build/`。原 Go checkout 的历史 `deployments/`、`optimization/` 仍留在本地。若发布结果摘要，先审核凭据与设备私有数据，不上传 SSH key/token/密码、生产配置或未经审核的部署日志。
