# Binding of the IP stack to an adapter can lag the first service start after
# specialize, and a family can be unbound on an adapter altogether. The
# MSFT_NetIPInterface object is then absent and Set-NetIPInterface can only
# fail, so every family is looked up first. One shared deadline bounds the
# waiting for the whole script, so many unbound families cannot add up.
$netIpWaitSeconds = 60
$netIpPollSeconds = 2
$netIpDeadline = $null

function Write-VirtainerWarning([string]$message) {
    [Console]::Out.WriteLine('VIRTAINER-HELPER-WARNING|' + ($message -replace '[\r\n]+', ' '))
}

# Only a query that matched nothing means "absent". The localized message
# text is never inspected: the CIM error category and FullyQualifiedErrorId
# identify it. Any other error (provider or CIM failure) is not absence; it
# is retried until the deadline and then thrown, never turned into a skip.
function Test-VirtainerNotFound($err) {
    return ($err.CategoryInfo.Category -eq 'ObjectNotFound') -or
        ([string]$err.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*')
}

function Wait-VirtainerNetIPInterface([uint32]$index, [string]$family) {
    if ($null -eq $script:netIpDeadline) {
        $script:netIpDeadline = (Get-Date).AddSeconds($netIpWaitSeconds)
    }
    while ($true) {
        $failure = $null
        try {
            $found = Get-NetIPInterface -InterfaceIndex $index -AddressFamily $family -ErrorAction Stop
            if ($found) { return $found }
        } catch {
            if (-not (Test-VirtainerNotFound $_)) { $failure = $_ }
        }
        if ((Get-Date) -ge $script:netIpDeadline) {
            if ($failure) { throw $failure }
            return $null
        }
        Start-Sleep -Seconds $netIpPollSeconds
    }
}

function Reset-VirtainerDhcp([uint32]$index) {
    $renew = $null
    $present = @()
    foreach ($family in @('IPv4', 'IPv6')) {
        $current = Wait-VirtainerNetIPInterface $index $family
        if (-not $current) {
            Write-VirtainerWarning ('adapter ifIndex {0} has no {1} interface; skipping {1} DHCP configuration' -f $index, $family)
            continue
        }
        $present += $family
        # An interface that already has DHCP is left as it is. Re-applying
        # Enabled drops its lease back to APIPA, and Windows then stops
        # sending DISCOVER. Its routes are not removed either: the default
        # route the DHCP client installs is also reported as NetMgmt, and a
        # renew does not put it back.
        if ($current.Dhcp -ne 'Enabled') {
            # Switching from static: remove the manual addresses and the
            # static default route before DHCP takes over.
            Get-NetIPAddress -InterfaceIndex $index -AddressFamily $family -ErrorAction SilentlyContinue |
                Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notlike 'fe80:*' } | Remove-NetIPAddress -Confirm:$false
            $destination = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
            Get-NetRoute -InterfaceIndex $index -DestinationPrefix $destination -ErrorAction SilentlyContinue |
                Where-Object { $_.Protocol -eq 'NetMgmt' } | Remove-NetRoute -Confirm:$false
            Set-NetIPInterface -InterfaceIndex $index -AddressFamily $family -Dhcp Enabled
            if ($family -eq 'IPv4') { $renew = $current.InterfaceAlias }
        }
        if ($family -eq 'IPv6') {
            Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -RouterDiscovery Enabled
        }
    }
    # Renew in the background: with no DHCP server reachable, a synchronous
    # renew waits out its retries and would hold up the rest of provisioning.
    if ($renew) {
        Start-Process -FilePath ipconfig.exe -ArgumentList '/renew', ('"{0}"' -f $renew) -WindowStyle Hidden
    }
    if ($present.Count) { Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses }
}

$adapters = @(Get-NetAdapter -IncludeHidden)
function Require-VirtainerNetIPInterface([uint32]$index, [string]$mac, [string]$family) {
    if (-not (Wait-VirtainerNetIPInterface $index $family)) {
        throw ('adapter {0} has no {1} interface; cannot apply the requested static {1} configuration' -f $mac, $family)
    }
}

function Find-VirtainerAdapter([string]$mac) {
    $matching = @($adapters | Where-Object { $_.MacAddress -and $_.MacAddress.Replace('-', ':') -ieq $mac })
    if ($matching.Count -ne 1) { throw 'MAC must resolve to exactly one adapter' }
    return $matching[0].ifIndex
}

if ($p.dhcp_all) {
    foreach ($a in @($adapters | Where-Object { $_.HardwareInterface })) {
        Reset-VirtainerDhcp $a.ifIndex
    }
} else {
    foreach ($mac in $p.dhcp_macs) {
        Reset-VirtainerDhcp (Find-VirtainerAdapter $mac)
    }
}
foreach ($n in $p.static) {
    $index = Find-VirtainerAdapter $n.mac
    foreach ($family in @('IPv4', 'IPv6')) {
        $addresses = @($n.addresses | Where-Object { ([ipaddress]($_.Split('/')[0])).AddressFamily.ToString() -eq $(if ($family -eq 'IPv4') { 'InterNetwork' } else { 'InterNetworkV6' }) })
        if ($addresses.Count -eq 0) { continue }
        Require-VirtainerNetIPInterface $index $n.mac $family
        Set-NetIPInterface -InterfaceIndex $index -AddressFamily $family -Dhcp Disabled
        Get-NetIPAddress -InterfaceIndex $index -AddressFamily $family -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike 'fe80:*' } | Remove-NetIPAddress -Confirm:$false
        $default = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
        Get-NetRoute -InterfaceIndex $index -DestinationPrefix $default -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false
        foreach ($address in $addresses) {
            $parts = $address.Split('/')
            New-NetIPAddress -InterfaceIndex $index -IPAddress $parts[0] -PrefixLength ([byte]$parts[1]) | Out-Null
        }
    }
    if ($n.gateway) {
        Require-VirtainerNetIPInterface $index $n.mac $(if (([ipaddress]$n.gateway).AddressFamily -eq 'InterNetwork') { 'IPv4' } else { 'IPv6' })
        $destination = if (([ipaddress]$n.gateway).AddressFamily -eq 'InterNetwork') { '0.0.0.0/0' } else { '::/0' }
        New-NetRoute -InterfaceIndex $index -DestinationPrefix $destination -NextHop $n.gateway | Out-Null
    }
    if (@($n.dns).Count) { Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $n.dns }
    else { Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses }
}
