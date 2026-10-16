# 请做一次整体架构与代码审阅

请先读README、ARCHITECTURE和CURRENT_FAILURE，再直接检查真实源码。此包是脱敏review-only副本，配置/历史raw/F9/秘密已删除，`None`不代表生产原方法允许缺省。不要运行硬件、SSH、Root、服务、RPC、Manager、模型、下载或数据库写入。不要把compile绿或源码缺少现场数据当成部署资格。

请以代码具体文件/函数/分支为依据，回答以下问题；对不能从源码证明的点标unknown，并把事实、推断和建议分开：

1. 架构复杂度是否已过高？哪些层是必要的authority/资源隔离，哪些递归历史/source验证或动态loader是重复责任？有没有保完整不变式的最小简化顺序，而非再追加一层wrapper？
2. 当前owner paired finish14.379秒后activation又耗23.241秒，原因是完整source-context/current_epoch/history递归与1179次compile的哪些具体调用？可固定历史事实与必须fresh事实的边界在哪里？怎样减少重复而不缓存陈旧授权？
3. owner恢复的intent/completed/fence、actor terminal与同Runtime维护释放是否原子？partial commit、异常尾、重启、warm重入、metadata换inode/同bytes与fresh再检查会怎样？请找潜在无法恢复或重复提交窗口。
4. 当前维护held/failed-owner下正常停启、旧Runtime close失败、lease释放、完整CG/PID终态以及新sole顺序如何证明？有无用generic退出码冒具体原因、或finally掩盖异常的风险？
5. PC/A/Mac不同钟域、PC5/A5/age10/whole30/entry90/whole1800与浮点等式如何正确组合？哪些操作被错误放到BEGIN后或deadline尾？绝不能以延长时限解决。
6. Root sender、UID999 service、私有Namespace/module table、source pin/held FD/F9、package metadata与sys.path保护有没有旁路、误共享或难维护的耦合？不要建议提高service权限或放宽Root gate。
7. 成熟框架或已有标准模式能替代哪些自制部分（事务状态机、durable workflow、结构化并发、schema/协议、process supervisor、不可变内容存储）？说明具体收益、集成成本、迁移风险和最小适用范围；不要泛泛推荐重写整套或增加网络/守护权限。
8. 普通25父入口与恢复前序、exact terminal选择、late response/EOF/rc/cap和deadline证据怎样避免“资产已接受但父失败又重跑”？哪些typed结果应分层交付？

交付格式：按严重度列具体finding（文件/函数/可触发条件/影响/决定性代码证据/最小修复/必要正负验证）；随后给一段整体判断与最多三个优先修复单元。若未发现确定bug，也应指出无法从脱敏包验证的必要证据，不制造finding。不要输出或请求秘密，不推断缺失原件内容，不声称可以直接部署。
