# 当前明确失败：owner恢复activation越过原PC whole30

这是实际结果摘要，不包含原始receipt、nonce、PID、boot或机器身份。所有旧阶段永久spent，不允许重新发送以确认。

1. R16正常epoch、独立source qualification已实际成功，控制服务唯一运行。
2. 新owner permit / PC BEGIN / A readonly / ownedstop / PC finish均一次成功；PCfinish whole为 **14.378944276 秒**，完整qualified已生成。
3. 同进程随后 original RootRPC activation sent1。实际private RPC用时 **23.240539148 秒**，明确抛 `owner_Refused`，固定原因 **`owner_release_new_PC_final_whole30`**。
4. 两段累计已超过原30秒。维护仍held，owner释放没有接受。不能把finish成功或服务仍活着等同恢复成功。

## 已获得的性能分解

- 直接校验旧terminal A原件约 **0.152秒**。
- source-context相关完整路径约 **9.423秒**。
- current epoch verify相关路径约 **8.651秒**，观察到 **1179次compile**。

这些时间来自同次因果调查，部分可能嵌套，**不能机械相加**。现有证据更指向重复历史/源验证与动态加载成本；不能把I/O写成已证主要瓶颈，也不能据此删除门。当前导出只供寻找可证明安全的最小重构。

## 已知更早问题，不能混为本次原因

- 旧普通下载曾遇CDN connect阶段TLS reset104；当次分类明确，底层唯一原因仍unknown。后续匿名TLS/noSNI比较与下载body资格不同，不应改SNI、CA、Range206、length/EOF/SHA或系统网络来碰运气。
- 早期父端完整pulse运输曾挤压原5秒门。R3无损pulse8去重与实际fullframe运输方法已有独立接受，不等于任何新pulse天然及时。
- 大终态回执约1.927MB，旧运输耗25.7秒并导致旧finish age30拒。后续large opaque XZ方法真实历史运输有余量，但不构成新owner释放许可，也不免除服务端历史复核成本。

## 请审的直接路径

`installed/PC/service/history_reader.py（共置owner_*方法）` 的fresh/历史/commit尾与normal/activation接线；`prelaunch_recovery.py`；`current_epoch.py`；phase history/pc recovery/OldContext；再对照 `runtime118/B_OWNER_RECOVERY_R25_WIRING/wiring.py`、`hx_service/service.py`、composition close与共享scheduler锁。

禁止提出“延长30秒/5秒”“重发旧nonce”“直接SQL释放”“删used/旧证据”“同进程假Root角色”“第二Manager”等作为修复。可以提出需要新有限source epoch的最小候选，但必须说明原子性、权限和历史重入证明，以及如何在实际控制held态安全过渡。
