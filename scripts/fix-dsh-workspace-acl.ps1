param(
  [Parameter(Position=0)] [string]$Path = (Get-Location).Path,
  [string]$AllowRoot = $Path,
  [string]$Out = "$Path-acl-recovery",
  [switch]$CheckOnly,
  [string]$Restore
)

$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8

if ($PSVersionTable.PSVersion.Major -lt 7) { Write-Output 'FAIL PowerShell7Required'; exit 4 }

$typeName='DshAclNative'
if (-not ([System.Management.Automation.PSTypeName]$typeName).Type) {
  $native=@'
using System;
using System.Runtime.InteropServices;
public static class DshAclNative {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hObject);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSDRevision, out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, out bool bDaclPresent, out IntPtr pDacl, out bool bDaclDefaulted);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern uint SetNamedSecurityInfoW(string pObjectName, int ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr LocalFree(IntPtr hMem);
}
'@
  Add-Type -TypeDefinition $native
}

function Test-Right([string]$p,[uint32]$mask) {
  $h=[DshAclNative]::CreateFileW($p,$mask,7,[IntPtr]::Zero,3,0x02000000,[IntPtr]::Zero)
  if ($h -eq [IntPtr]::Zero) { return $false }
  [void][DshAclNative]::CloseHandle($h)
  return $true
}

function Get-Ctx([string]$p) {
  $sd=Get-Acl -LiteralPath $p
  $owner=$sd.GetOwner([Security.Principal.SecurityIdentifier]).Value
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  [pscustomobject]@{
    Path=(Resolve-Path -LiteralPath $p).ProviderPath
    Owner=$owner
    CurrentSid=$sid
    WriteDac=(Test-Right (Resolve-Path -LiteralPath $p).ProviderPath 0x00040000)
    WriteOwner=(Test-Right (Resolve-Path -LiteralPath $p).ProviderPath 0x00080000)
    Sddl=$sd.GetSecurityDescriptorSddlForm('Access')
  }
}

function Set-Dacl([string]$p,[string]$sddl) {
  $sd=[IntPtr]::Zero
  $size=[uint32]0
  if (-not [DshAclNative]::ConvertStringSecurityDescriptorToSecurityDescriptorW($sddl,1,[ref]$sd,[ref]$size)) {
    throw "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: $sddl"
  }
  try {
    $dacl=[IntPtr]::Zero
    $present=$false
    $defaulted=$false
    [void][DshAclNative]::GetSecurityDescriptorDacl($sd,[ref]$present,[ref]$dacl,[ref]$defaulted)
    if (-not $present -or $dacl -eq [IntPtr]::Zero) { throw "No DACL in $sddl" }
    $result=[DshAclNative]::SetNamedSecurityInfoW($p,1,0x0004,[IntPtr]::Zero,[IntPtr]::Zero,$dacl,[IntPtr]::Zero)
    if ($result -ne 0) { throw "SetNamedSecurityInfoW failed: $result" }
  } finally {
    if ($sd -ne [IntPtr]::Zero) { [void][DshAclNative]::LocalFree($sd) }
  }
}

function Assert-Scope([string]$full,[string]$root) {
  if ($full -eq $root -or $full.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { return }
  Write-Output "REFUSED outside AllowRoot: $full not under $root"
  exit 5
}

function Esc([string]$v) { return ($v -replace "'","''") }

if ($Restore) {
  $full=(Resolve-Path -LiteralPath $Path).ProviderPath
  $root=(Resolve-Path -LiteralPath $AllowRoot).ProviderPath
  Assert-Scope $full $root
  $json=Get-Content -LiteralPath $Restore -Raw -Encoding UTF8 | ConvertFrom-Json
  $currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($json.path -ne $full) { Write-Output "REFUSED backup path mismatch: $($json.path) != $full"; exit 5 }
  if ($json.sid -ne $currentSid) { Write-Output "REFUSED backup SID mismatch: $($json.sid) != $currentSid"; exit 5 }
  Set-Dacl $full $json.sddl
  Write-Output "RESTORED $full from $Restore"
  exit 0
}

$full=(Resolve-Path -LiteralPath $Path).ProviderPath
$root=(Resolve-Path -LiteralPath $AllowRoot).ProviderPath
Assert-Scope $full $root
$before=Get-Ctx $full

Write-Output ("OBJECT="+$before.Path)
Write-Output ("OWNER="+$before.Owner)
Write-Output ("CURRENT_SID="+$before.CurrentSid)
Write-Output ("WRITE_DAC="+$before.WriteDac)
Write-Output ("WRITE_OWNER="+$before.WriteOwner)

if ($CheckOnly) {
  if ($before.WriteDac -and $before.WriteOwner) { Write-Output 'VERDICT=OK'; exit 0 }
  Write-Output 'VERDICT=PRECONDITION'; exit 2
}

if ($before.WriteDac -and $before.WriteOwner) { Write-Output 'VERDICT=ALREADY_OK'; exit 0 }
Write-Output 'VERDICT=PRECONDITION'

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$stamp=Get-Date -Format 'yyyyMMddHHmmss'
$jsonPath=Join-Path $Out "acl-backup-$stamp.json"
$ps1Path="$jsonPath.ps1"
$reportPath=Join-Path $Out "acl-report-$stamp.json"

$backup=[ordered]@{path=$full;allowRoot=$root;sid=$before.CurrentSid;owner=$before.Owner;sddl=$before.Sddl;created=(Get-Date).ToString('o')}
$backup | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$self=(Resolve-Path -LiteralPath $PSCommandPath).ProviderPath
$rollback="pwsh -NoProfile -File '"+(Esc $self)+"' -Path '"+(Esc $full)+"' -AllowRoot '"+(Esc $root)+"' -Restore '"+(Esc $jsonPath)+"'"
$rollback | Set-Content -LiteralPath $ps1Path -Encoding UTF8

Write-Output "BACKUP $full -> $jsonPath"
Write-Output ("ROLLBACK pwsh -NoProfile -File '"+(Esc $ps1Path)+"'")

$newSddl=$before.Sddl + '(A;;FA;;;' + $before.CurrentSid + ')'
Set-Dacl $full $newSddl
Write-Output ("GRANTED "+$full+" SID="+$before.CurrentSid)

$after=Get-Ctx $full
$verified=($after.WriteDac -and $after.WriteOwner)
$result=[ordered]@{
  path=$full
  before=@{writeDac=$before.WriteDac;writeOwner=$before.WriteOwner}
  after=@{writeDac=$after.WriteDac;writeOwner=$after.WriteOwner}
  verified=$verified
  backup=$jsonPath
  rollbackScript=$ps1Path
}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Output ("RECAP "+($result | ConvertTo-Json -Compress -Depth 5))
Write-Output "REPORT_FILE $reportPath"
if ($verified) { Write-Output 'SUMMARY GRANTED=1 VERIFIED=1'; exit 0 }
Write-Output 'SUMMARY GRANTED=1 VERIFIED=0'
Write-Output 'FAILED verification after grant; stop. Restore with ROLLBACK if needed.'
exit 3
