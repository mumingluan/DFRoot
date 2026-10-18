# DFRoot vivo 加固分支（二开工作区）

上游 `diabl0w/DFRoot` @ master `0fed9a8`（v4.5, 2026-10-16）。
本分支目标：给 vivo（iQOO 15, PD2505D, 6.12.23-android16-5）补齐与
GhostLock 相当的成功后健壮性，不改变上游对其他厂商的路径。

## 三项加固（本批次范围）

1. **W1c 等价：vr.ko sys_exit 回调清零**（ko 层，UMH 前）
   - 依据：GhostLock 在该设备上实证 `__tracepoint_sys_exit + 72` 为
     vr.ko 注册的 funcs 数组地址（设备 profile：
     `offset.sys_exit_tp_funcs = 39405704`，`vr_guard.tracepoint_funcs = 72`）。
   - 实现：ko 内通过 `get_addr("__tracepoint_sys_exit")` 取基址，加 72
     读出 funcs 指针，校验非空且指向模块地址空间后清零。
   - 门禁：仅当 `vr` 模块已加载（`/sys/module/vr` 或 module kallsyms
     能查到 `vr` 名下符号）时执行；非 vivo 设备完全跳过，不碰共享
     tracepoint。
2. **KSU 已加载拒绝重跑**（ko 层，最早阶段）
   - 实现：module kallsyms 查 `ksu_handle_execveat_ksud` 或存在
     `/proc/ksu`（内核 5.10+ 可 `kernel_read_file` 探测；ko 层退化为
     module kallsyms 查 kernelsu 符号）。命中即 return -EEXIST。
3. **ksud 成功后恢复 enforcing**（bootstrap.c）
   - 实现：late-load 返回 0 后，写 `/sys/fs/selinux/enforce` 为 1；
     失败不致命（记 /dev/dfmw2），因为 SELinux 恢复尽力而为。

## 不做的事（明确保留）

- 不动 exploit 本体（exp.c / libcxx.S / splicehelper.c / elf_parser.c）。
- 不动 SELinux patch 策略（avc_has_perm/noaudit 永久 patch 保留）——
  恢复 enforcing 依赖这些 patch 仍然生效才能在 enforcing 下工作，
  详见下文"恢复语义"。
- 不引入 profile 系统；偏移 72 以带注释常量进入 ko，来源注释指向
  GhostLock 设备证据。
- 上游 Makefile 的 8-KMI DDK 容器构建不动；验证走 GitHub Actions。

## 恢复语义（重要设计约束）

v4.5 的 ko 把 `avc_has_perm` / `avc_has_perm_noaudit` patch 成恒返 0。
若在 ksud 完成后把 `selinux_state` 写回 true，一切 AVC 走 noaudit 路径
仍返回 0，策略名义 enforcing、实际放行——形成"半 enforcing"状态。
GhostLock 的做法是 policy reload + 恢复，其内核态原语本就恢复原样。
DFRoot 无内核态恢复原语，故本分支的"恢复"仅指 **re-enable
`selinux_state`（dev 表）/写 enforce 节点**，并把 avc patch 逆向为
恢复原始指令需要保存原指令——上游未保存。因此：
- 方案 A（本批次采用）：**不 patch avc 函数**（去掉该步），ksud 期间
  依赖 `selinux_state=false` 的 permissive；完成后写回 true。若目标
  内核 CONFIG_SECURITY_SELINUX_DEVELOP=n，则保持上游行为（patch avc）
  并跳过恢复。
- 恢复动作放 bootstrap（用户态 root，域 init），写 enforce 文件即可
  生效（security_load_policy 路径之外的最小路径）。

## 验证

- ko：GitHub Actions DDK 容器（android16-6.12）编译 + 每符号尺寸监控
  （上游 Makefile 的 strip 目标保留）；主机语法检查用
  `clang --target=aarch64-linux-gnu -fsyntax-only`。
- 真机（用户侧）：冷启动、KSU 未加载、DFRoot 单跑；观察管理器打开
  不死机、`getenforce` 显示 Enforcing、重启后一切如常。
- 构建 APK 需 ko 产物就位；本地无容器环境，先出代码与 Actions 构建。

## 提交规范

`type(scope): summary`；ko 改动记 `lkm/`，bootstrap 改动记 `jni/`。
