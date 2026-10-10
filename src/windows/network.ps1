# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors

function Reset-VirtainerDhcp([uint32]$index) {
    foreach ($family in @('IPv4', 'IPv6')) {
        Get-NetIPAddress -InterfaceIndex $index -AddressFamily $family -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notlike 'fe80:*' } | Remove-NetIPAddress -Confirm:$false
        $destination = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
        Get-NetRoute -InterfaceIndex $index -DestinationPrefix $destination -ErrorAction SilentlyContinue |
            Where-Object { $_.Protocol -eq 'NetMgmt' } | Remove-NetRoute -Confirm:$false
        Set-NetIPInterface -InterfaceIndex $index -AddressFamily $family -Dhcp Enabled
    }
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -RouterDiscovery Enabled
    Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses
}

$adapters = @(Get-NetAdapter -IncludeHidden)
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
        $destination = if (([ipaddress]$n.gateway).AddressFamily -eq 'InterNetwork') { '0.0.0.0/0' } else { '::/0' }
        New-NetRoute -InterfaceIndex $index -DestinationPrefix $destination -NextHop $n.gateway | Out-Null
    }
    if (@($n.dns).Count) { Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $n.dns }
    else { Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses }
}
