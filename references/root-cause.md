# 根因与边界（只读参考）

## 一句话结论
DSH 在 Windows 上给工作区写 capability allow ACE、world deny ACE 和 Low mandatory label 时，用一次 SetNamedSecurityInfoW 同时改 DACL 与 SACL；SACL 的写入要求调用者对目标目录同时拥有 WRITE_DAC 和 WRITE_OWNER。工作区目录常被建成“所有者是当前用户、有 WRITE_DAC、但没有 WRITE_OWNER”，于是 grantWrite 抛 Win32 5。

## 精确报错
Error: code run failed (worker-exit): sandbox-local: windows-acl workspace grant failed: Win32Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\dsh\plugins\dsh-tool-manager). The command did not run; check that the current user can change permissions on the workspace and temp directories, or run with danger-full-access.

## 源码锚点
以下锚点在 DSH 0.2.2-rc.5 核对；其他版本按包相对路径搜索同名函数。
- 包相对路径 node_modules/@deepseek-ai/dsh-sandbox-windows-acl/src/acl.ts:8-15：每次 grant 一次 SetNamedSecurityInfoW，写 capability-SID allow、world SID 的 FILE_DELETE_CHILD deny、Low no-write-up label。
- src\acl.ts:255-259：SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, ...)。
- src\acl.ts:262：applyResult !== ERROR_SUCCESS 时 throwWin32(..., SetNamedSecurityInfoW, ...)。
- src\acl.ts:368-370 原文：The directory must be owned by the caller AND grant WRITE_OWNER (the label lives in the SACL; owner-implicit rights cover only READ_CONTROL and WRITE_DAC) — a Full-control workspace satisfies both.
- src\index.ts:268-279：manageDacls 对每个 writableDir 调 grantWrite。

## S-1-5 不是通用修法
- S-1-5-18 = LocalSystem，是 D:\ 根目录的 owner，不是你的登录账户。
- S-1-5-11 = Authenticated Users。
- S-1-5-21-...-1001 = 当前本地/域用户，才是授权目标。
- S-1-4-... = 应用包/能力 SID，由 DSH 动态写入，不要手填。
给普通目录加 S-1-5-18:(F) 不会让 DSH 以你的身份拿到权限，也没有必要。

## 已验证的修复形状
1. 对目标目录做只读 CreateFileW 探针：WRITE_DAC=OK、WRITE_OWNER=ERR=5。
2. 备份 DACL SDDL，生成独立 .ps1 回滚脚本。
3. 给当前用户 SID 加一条 FullControl allow ACE（保留 deny ACE、owner、SACL）。
4. 再探针：WRITE_DAC=OK、WRITE_OWNER=OK。
5. 普通 confined run_code 复验原操作，exit 0。

## PowerShell 陷阱
Windows PowerShell 5.1 在 PSModulePath 把 D:\soft\PowerShell7\7\Modules 排在系统模块前时，会加载 PS7 版 Microsoft.PowerShell.Security 失败，Get-Acl 消失（CommandNotFoundException=0x80131501 / win32=5377）。用 pwsh 7 或 icacls 绕开。

## 不要做
- 不要删 Everyone:(I)(CI)(DENY)(DC) 或 Low Mandatory Level。
- 不要改所有者。
- 不要在 confined workspace-write 工具里直接跑修复；内层 pwsh 也要单独给 danger-full-access。
- 修复失败一次即停止，不重试、不手改。
