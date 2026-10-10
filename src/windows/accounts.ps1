# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors

if ($p.admin) {
    $password = ConvertTo-SecureString -String $p.admin.password -AsPlainText -Force
    $user = Get-LocalUser -Name $p.admin.username -ErrorAction SilentlyContinue
    if ($user) {
        Set-LocalUser -InputObject $user -Password $password
        Enable-LocalUser -InputObject $user
    } else {
        $user = New-LocalUser -Name $p.admin.username -Password $password
    }
    $group = Get-LocalGroup -SID 'S-1-5-32-544'
    $members = @(Get-LocalGroupMember -Group $group)
    if (-not ($members | Where-Object { $_.SID -eq $user.SID })) {
        Add-LocalGroupMember -Group $group -Member $user
    }
}
if ($p.timezone) { Set-TimeZone -Id $p.timezone }
$directory = Join-Path $env:ProgramData 'ssh'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'SSH directory is a reparse point'
}
$directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = [Security.Principal.SecurityIdentifier]::new($sid)
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
$directoryAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
Set-Acl -LiteralPath $directory -AclObject $directoryAcl
$path = Join-Path $directory 'administrators_authorized_keys'
# Stop before writing a link planted by another account.
if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'authorized keys path is a reparse point'
}
# A read-only file left in the image (for example copied from install media) blocks the write.
if (Test-Path -LiteralPath $path) {
    $existing = Get-Item -LiteralPath $path -Force
    if ($existing.Attributes -band [IO.FileAttributes]::ReadOnly) {
        $existing.Attributes = $existing.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
    }
}
$content = if (@($p.keys).Count) { ($p.keys -join "`n") + "`n" } else { '' }
[IO.File]::WriteAllText($path, $content, [Text.UTF8Encoding]::new($false))
$acl = [Security.AccessControl.FileSecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = [Security.Principal.SecurityIdentifier]::new($sid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow'))
}
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
Set-Acl -LiteralPath $path -AclObject $acl
