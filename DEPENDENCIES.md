# 依赖、缺省与红线

## 静态源码依赖

当前导出源码的静态import主要为Python标准库和本项目内部模块；没有vendor第三方库或模型。标准库包括socket/ssl/http.client/urllib、subprocess/select、threading/concurrent、fcntl/resource、sqlite3、hashlib/json/base64/zlib/lzma、ast/importlib/types等。`lzma`大帧codec是后续父方法资格，不是服务恢复资格。

`integration`是原生成器私有加载器使用的逻辑模块名，不是建议从PyPI安装的第三方包。安装路径、source bundle、旧域namespace及配置/原件等未随本包提供，不能靠ambient import补齐。未附requirements锁文件，因为本包不提供可执行部署环境；不要对照import名字自动pip install。

生产操作还依赖Linux systemd/proc/cgroup/flock、PC的WSL/Windows SSH中转、A的containerd/ctr/runc及网络/TLS工具。它们不是本仓库附带的driver、安装脚本或权限授权，审阅时不得执行。模型tokenizer/renderer/镜像/权重、SSH/known-hosts/配置和真实scope资源数据均排除。

## 缺失数据是有意的

- 当前及历史配置、source bundle、packed histories、raw/F9/receipt、DB、ledger、SSE、模型思考和用户资料不公开。
- 部署策略/身份/原件大常量改成`None`；可解析的嵌入Python移到`embedded/`单独审阅。敏感路径/地址/UUID/运维nonce作一致替换。不能把它们当生产值。
- `EXPORT_MANIFEST.json`标记改动位置、原源SHA与导出SHA。原SHA只用于来源对照，不表示本脱敏文件通过原source qualification。
- 许可与第三方版权请见NOTICES；没有对整个仓库添加MIT。

## 审阅红线

不运行installed、runtime118、parent25、parent_support或generators中的入口；不接触硬件/网络/模型/RootRPC；不发旧nonce或新请求；不延长5/10/30/90/1800；不删used/历史；不SQL释放；不提高service权限或并行第二Manager。

仅`repros/float_deadline.py`和`repros/deadline_order.py`是无I/O的纯数字例子，仍不是生产proof或目标性能测试。需要更多现场证据时，请列最小缺项交由系统所有者判断，不自行操作。
