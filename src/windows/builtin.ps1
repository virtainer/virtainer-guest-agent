# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors

# The built-in Administrator may be renamed or localized: resolve it as the
# machine SID plus RID 500, taking the machine SID from the local account that
# must stay enabled.
$user = Get-LocalUser -Name $p.username
$group = Get-LocalGroup -SID 'S-1-5-32-544'
if (-not (@(Get-LocalGroupMember -Group $group) | Where-Object { $_.SID -eq $user.SID })) {
    throw 'administrator account is not in the Administrators group'
}
$sid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::AccountAdministratorSid, $user.SID.AccountDomainSid)
$builtin = Get-LocalUser -SID $sid
if ($builtin.SID -eq $user.SID) {
    throw 'admin.username is the built-in Administrator account; it was not disabled'
}
if ($builtin.Enabled) {
    Disable-LocalUser -InputObject $builtin
}
