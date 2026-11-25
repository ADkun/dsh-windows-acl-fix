---
name: dsh-windows-acl-fix
description: Windows 下 DSH 沙箱 ACL 的定向回退技能。当已定位为单个工作区根目录缺 WRITE_OWNER，或内置 diagnose-windows-sandbox-acl 不可用/因 PowerShell 5.1 模块污染失败时，用 pwsh 7 做 DACL-only 最小授权修复与备份回滚；覆盖 windows-acl workspace grant failed、SetNamedSecurityInfoW failed (Win32 5)、grantWrite(<path>) 三类报错，产出诊断结论、回滚命令与 confined 复验。
---

# DSH Windows ACL 定向修复

## 核心目标与审美宣言
Risk-first，Minimalist，Evidence-first。只改一个目录的一条 allow ACE；不碰所有者、不删 deny ACE、不写 SACL、不猜 SID。先证明缺的是 WRITE_OWNER，再补当前用户 FullControl，最后让原来的 confined 操作自己说话。

## 与内置技能的分工
- 首选内置 diagnose-windows-sandbox-acl：意外的工作区写/列目录拒绝通常由它一次命令覆盖路径链、祖先与 temp 子树，并清理外来 S-1-15-2-* ACE。
- 本技能是定向回退，不是替代品。仅在两种情形使用：已确认只有一个工作区根目录缺 WRITE_OWNER，且需要 DACL-only、保留 owner/SACL、带显式回滚的修复；或内置脚本不可用/因 PS 5.1 PSModulePath 污染导致 Get-Acl 缺失。
- 内置技能可用且原因未定位时，不要与它并行或抢先；按内置技能一次命令完成。

## 触发与决策路由
- 只想理解原因 → 读 references/root-cause.md，不开写操作。
- 只想确认权限 → 跑脚本 -CheckOnly，只读，不修复。
- 已确认单个目录缺 WRITE_OWNER 且用户要求修 → 一次调用跑脚本（不带 -CheckOnly，给 -Out）；脚本内部先探针再修，不要拆成诊断调用加修复调用。
- 复验仍失败 → 停止，报告新报错；不要重复修复，不要手改权限。

## 核心工作流
### Phase 1: 可选只读侦察
- 执行指令：用 pwsh 7 运行 scripts/fix-dsh-workspace-acl.ps1 -Path 工作区 -CheckOnly。
- 退出条件：拿到 OWNER / CURRENT_SID / WRITE_DAC / WRITE_OWNER 四行；两者皆 True 则判定为已满足，转复验。

### Phase 2: 一次调用备份与最小授权
- 执行指令：确认目标在 -AllowRoot 内后，一次运行同一脚本（去掉 -CheckOnly，给 -Out）；脚本写 backup JSON 加独立 .ps1 回滚脚本，只给当前用户 SID 追加一条 FullControl allow ACE。
- 退出条件：RECAP 中 verified=true 且 before.writeOwner=false → after.writeOwner=true；ROLLBACK 行存在。

### Phase 3: 验证与交付
- 执行指令：用普通 confined run_code（不带 danger-full-access）重跑原始失败操作；同时回读报告与备份路径。
- 退出条件：confined 操作 exit 0；向用户报告修复成功、报告路径、回滚命令，并注明不要删 deny ACE。

## 执行约束与红线
- 不与内置 diagnose-windows-sandbox-acl 并行；内置可用且原因未定位时优先内置。
- 禁止用 Windows PowerShell 5.1；本机 PSModulePath 会把 PS7 的 Microsoft.PowerShell.Security 抢先加载，导致 Get-Acl 不存在。
- 禁止给 S-1-5-18 / S-1-5-11 授权；那是 LocalSystem / Authenticated Users，不是当前用户。
- 禁止删除 Everyone:(I)(CI)(DENY)(DC) 或 Low Mandatory Level；它们是沙箱隔离的一部分。
- 禁止在 workspace-write 的 confined 工具里直接跑修复；内层 pwsh 也要单独给 danger-full-access。
- 一次修复失败即停止，不重试、不手改 ACL、不扩大授权范围。

## 资源引用
- scripts/fix-dsh-workspace-acl.ps1：唯一的执行入口，用 -? 查看帮助；-CheckOnly 只读。
- references/root-cause.md：证据与边界；grep 关键词：Win32 5、WRITE_OWNER、S-1-5-18、SetNamedSecurityInfoW。
- evals/trigger-eval.json：触发评测题目，改 description 后复跑。
