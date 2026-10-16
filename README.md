# DGX Home AI：当前 R16 源码审阅包

这是供外部架构与代码审阅的**脱敏源码快照**，不是安装包，也不是部署完成声明。它包含真实方法体、权限和时钟 gate；部署策略、原件、凭据及机器身份常量已删去或替换。`None` 是明确缺省，不能把本包的 SHA 或常量回填到生产。

## 当前真实状态

- PC 控制服务已完成 R16 正常顺序升级、独立资格验证，当前为唯一 Manager；当前恢复操作未完成，维护仍 held。
- 旧资产下载曾在 CDN TLS connect 阶段发生 reset errno104；这只是当次安全诊断记录，不能据此断言唯一网络根因。
- 已完成新 owner readonly paired scope 和 PC finish（14.378944276 秒）。随后同进程发送的实际 RootRPC activation 用时23.240539148秒，最终明确拒绝 `owner_release_new_PC_final_whole30`。不是未知运输结果，不能重发旧 nonce、旧 scope、旧 clock 或旧 finish。
- Qwen、GLM 都已通过普通 API 实际调用过，存在真实质量失败，不能把它们写成只下载或全部通过。Qwen部分固定结构长上下文任务成功；工具调用测试也有失败。GLM有推理耗尽输出额度、无最终答案，以及严格 JSON 格式失败等情况。
- MiMo / DeepSeek 相关工作目前是资产阶段，不能当已完成加载、推理或质量验收。完整镜像、全部模型和整套应用尚未宣布完成。

## 先读什么

1. [CURRENT_FAILURE.md](CURRENT_FAILURE.md)：最新明确拒绝、已知性能组成和未解决项。
2. [ARCHITECTURE.md](ARCHITECTURE.md)：PC服务、共享 Runtime、Root父入口、A只读/下载worker和证据链。
3. `installed/PC/service/history_reader.py（共置owner_*方法）`、`prelaunch_recovery.py`、`asset_stage.py`、`current_epoch.py`、`phase_histories*.py`（以实际目录文件名为准）。
4. `runtime118/deployment_integrations/composition.py`、`hx_service/service.py`、`B_OWNER_RECOVERY_R25_WIRING/wiring.py`、`control_plane/`、`llm_gateway/`。
5. `parent25/parent_entry.py`、`parent_io.py`、`parent_metadata.py`、`compact_transport.py`、`segment_parent.py`、`terminal_wait.py`；再看 `parent_support/` 和 `generators/`。
6. [GPT_PRO_REVIEW_PROMPT.md](GPT_PRO_REVIEW_PROMPT.md)：一次整体审阅的具体问题。

`EXPORT_MANIFEST.json` 给出每个原始源码 SHA 与导出 SHA、数据常量 redaction 的位置和理由。376个来源Python文件中包含23个从原字符串/bytes提取的嵌入 Python 源，位于 `embedded/`；其原大常量被置为缺省。所有配置、历史完整原件及现场授权均不包含在本包。

## 严格边界

不运行硬件、服务、SSH、Root、RPC、模型或下载；不创建 Manager、不执行 epoch、不重试资产、不编辑数据库、不回填策略。请只静态分析，极小数学复现仅使用自造数字。脱敏导致本包无法直接 import 成一个可运行系统，完整 compile 只证明语法，不代表权限、历史和真实时限 gate 通过。

文件头中的 `REVIEW-ONLY SANITIZED SOURCE` 表明脱敏版本。所有生产原件均保持不变。发布前仍需任务所有者二次审查本地卫生报告；本导出任务不创建仓库、不 push、不向 GPT 发送内容。

脱敏方式、结构对照和局限详见 [SANITIZATION.md](SANITIZATION.md)；本快照状态来自任务所有者已有原件，导出期间未重新查询现场。
