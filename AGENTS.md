# 开发与验证规则

本文件适用于此独立 mosdns-rust 仓库。遵循用户已经明确的流程：本地修改、push 到 `xfy-see/mosdns-rust`、在 GitHub 编译、下载到本地完整测试校验。

## 源码与兼容范围

- Rust 后续实现、测试、CI 和文档仅提交到本仓库；原 Go checkout 作为外部行为/性能基线，不混入本次 Rust 提交。
- 初期继续保留 `rust/` workspace、`coremain → plugin → pkg` 模块、plugin/sequence/query context 和配置语义；重构或行为变化先补充可复现测试。
- 复用 `tests/fixtures/`，保留 Go/Rust 共用的输入和预期值。修改预期结果必须说明原因并验证两端；默认测试不得重写 fixture。
- full 与 minimal 分别测试。minimal 必须关闭默认 feature，不能以 feature 合并的测试 CLI 代替独立生产 binary；权限/平台限制逐项记录。
- 保留 GPL 许可证和原版权声明。固定 TLS 私钥不得提交，即便被标为 mock/public fixture；真实设备凭据也不得用作测试输入。TLS 测试证书/key 仅在 GitHub Actions 临时生成，保持 Rust include 路径不变，不通过修改 .rs 来内联旧固定 key。
- 六个生成路径由 .gitignore 精确排除，不进入 Git index 或公开提交历史。两个私钥文件不得进入 runtime-source 或下载 artifact；四个公开测试证书可用于运行测试，但必须在 `generated_test_inputs` 中单独绑定。harness 可以内嵌本轮一次性的 localhost mock 素材，不能复用旧固定私钥。
- `ci/generate-test-fixtures.py` 只允许 `GITHUB_ACTIONS=true` 的 CI 生成，保持 .rs 原 SHA。`generated_test_inputs` 记录生成方法/路径、大小与 SHA；生成输入不混入 Git 跟踪源码树。两个明文私钥文件、CA 私钥与私钥内容不写入 artifact、日志或报告，编译后清理；不得导入系统 CA store。

## 本地操作与 GitHub 编译

- 本地 Rust 编译环境已经清理。不得默认安装 rustup/Cargo/target/依赖，也不得在本地执行 Cargo build/test/fmt/clippy；这些在 GitHub Actions 执行。用户另行明确要求本地编译时再调整。
- 本地可以进行文件审查、`git diff --check`、配置/JSON/YAML 检查、Python 脚本检查，以及运行已经下载并校验的 CLI/test harness；不要为静态检查恢复 Rust 环境。
- 提交前只 stage 本任务源码、测试、文档和 CI。检查暂存 diff 与敏感文件；push 后记录完整 commit SHA、workflow/run ID、状态与结论。
- 本仓库 `.github/workflows/build.yml` 定义编译矩阵。Rust 工具链与构建依赖只能在 CI 中安装；依赖采用 Cargo.lock 与 `--locked`。正式 CLI 与测试 harness 分开构建、分别记录来源。
- GitHub workflow 失败需保留失败日志并修复后提交新 commit；不能下载其它 commit 的成功产物冒充当前提交。不得 force push 或改写历史来隐藏失败记录。

## 产物下载与验证

- 只下载明确匹配该完整 commit SHA 的构建产物。核对 run 的 `headSha`、artifact 的 target/profile、manifest 的源码与构建信息，以及每个文件的 SHA-256 和大小。
- 使用 `ci/download-and-test.py`；下载目录和输出证据目录必须新建，禁止覆盖已完成或失败的记录。需要设备执行的 ARM64 产物先在本地 `--verify-only`。
- 固定正式 CLI、全部 harness、不含生成私钥文件的 runtime-source、测试列表、编译/测试日志、manifest 和本地结果；`generated_test_inputs` 独立核对生成输入元数据，不能把它们当作 Git 源文件。上传设备后再次验证 SHA-256。下载后的文件不重新编译或替换。
- SHA 校验验证下载文件与清单一致，不独立证明源码正确；结论仍须绑定可信 GitHub run、commit、源码快照和实际运行证据。

## 完整运行与性能验证

- 对匹配本机架构的 full/minimal，完整运行下载的 test harness、CLI 回归与协议 mock。测试文件读取的源码/fixtures 必须使用 artifact 的冻结快照，不能混用未提交工作树。
- 用户已指定 `192.168.100.131` 可用于后续测试。远端执行前读当前 boot ID、架构、资源、配置与 nftables 状态；使用独立目录、测试端口和唯一测试对象，保留现有生产 DNS/服务/路由。
- 设备普通 harness 使用 `ci/test-router.py` 与 `ci/router-session.sh`，绑定 `--expected-commit`、`--source-root`、目标 boot ID、明确 SSH identity/known-hosts 和新结果目录。默认计划模式，指定 `--execute` 才运行；不要绕过脚本的文件 hash、进程归属、资源或前后状态检查。
- `--nft` 和 `--socket-options` 为明确的权限测试选项；`--ipset-probe` 仅查询 subsystem，不创建 set。131 缺少 IPSet 支持的历史事实需当前再次确认；失败/不可用单独记录 capability 原始结果，不能计入普通/权限测试通过数，不能报告 IPSet 元素互操作已验证。
- 默认 ignored 用例列为未执行；`SO_MARK/SO_BINDTODEVICE`、nftset/ipset 等权限用例只按逐项明确范围执行，记录实际读回与清理。目标不支持 IPSet 时应报告限制或实际失败，不能将 nftset 的通过推广为 ipset 已验证。
- 完整性能测试包含可复现 CN site/CN IP 策略、mock 分流选择验证、真实 DNS 响应验证、hot/cold/disabled cache、UDP/TCP、并发与重复轮次；Go 对照绑定外部冻结 binary/fixture/配置。分别报告 QPS、延迟、错误、RSS 和可执行文件体积。
- 记录 CLI/harness/配置/规则 hash、boot ID、采样计划和前后状态；设备重启、SSH 中断、配置变化或未跑完的矩阵保留原始失败与覆盖范围，另开目录重试。
- CI 通过不代表本机或设备完整验证；交叉编译不代表目标运行；响应正确不单独证明分流选对；pilot、部分回归或少量吞吐数据不代表完整性能矩阵。
- 清理只处理本次创建的进程、目录和内核测试对象；用 boot ID、PID 和精确 executable 路径确认归属，不杀其它进程、不覆盖生产配置。

## 证据与敏感数据

- 原 Go checkout 的历史 `deployments/`、`optimization/`、原始 benchmark、工具链和 private configs 留在原本地位置，不迁入公开仓库。
- 本地测试报告和下载产物默认放 `.build/` 或仓库外的新目录；发布摘要前审核并去除私钥、SSH 凭据、token、真实服务密码、设备生产配置和其它私有数据。不得把原始日志的敏感内容写入提交消息或 PR。
- 冻结原始证据，派生报告单独生成。每轮结论注明 commit、产物 SHA、平台、实际通过/失败/ignored 和未验证项；新 commit 必须重新构建并完成自己的验证。
