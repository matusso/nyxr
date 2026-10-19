# Routed-study topology and SackOpts control for an operator-owned Windows VM.
# Run elevated. Addresses and routes use ActiveStore only; teardown removes
# exactly what Setup added and restores the recorded IPv6 DHCP state.
param(
    [Parameter(Mandatory=$true)][ValidateSet('Setup','Teardown','SetSackOpts','ClearSackOpts','Status')][string]$Action,
    [string]$InterfaceIPv4 = '192.168.254.130',
    [string]$StateDirectory = 'C:\nyxr-hz66-routed'
)
$ErrorActionPreference = 'Stop'
$target4 = '10.66.22.2'; $target6 = 'fd66:66:22::2'
$routes = @(@{Prefix='10.66.21.0/24'; NextHop='10.66.22.3'}, @{Prefix='fd66:66:21::/64'; NextHop='fd66:66:22::3'})
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$adapter = @(Get-NetIPAddress -IPAddress $InterfaceIPv4 -AddressFamily IPv4)
if ($adapter.Count -ne 1) { throw 'Adapter selector is not uniquely assigned.' }
$index = $adapter[0].InterfaceIndex
function Get-State {
    $os = Get-CimInstance Win32_OperatingSystem
    $sack = Get-ItemProperty -Path $parameters -Name SackOpts -ErrorAction SilentlyContinue
    [ordered]@{
        utc = [DateTime]::UtcNow.ToString('o')
        last_boot_utc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        build = $os.BuildNumber
        sackopts_registry_present = [bool]$sack
        sackopts_registry_value = if ($sack) { $sack.SackOpts } else { $null }
        addresses = @(Get-NetIPAddress -InterfaceIndex $index | Select-Object IPAddress,AddressFamily,PrefixLength,AddressState,PolicyStore)
        routes = @(Get-NetRoute -InterfaceIndex $index | Select-Object DestinationPrefix,NextHop,RouteMetric,PolicyStore)
        interfaces = @(Get-NetIPInterface -InterfaceIndex $index | Select-Object AddressFamily,Dhcp,RouterDiscovery,Forwarding)
    }
}
switch ($Action) {
    'Setup' {
        if (Test-Path $StateDirectory) { throw 'Routed setup state already exists.' }
        foreach ($ip in @($target4,$target6)) {
            if (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue) { throw "Address $ip already assigned." }
        }
        New-Item -ItemType Directory -Path $StateDirectory | Out-Null
        $ipv6 = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6
        @{dhcp6 = [string]$ipv6.Dhcp; before = Get-State} | ConvertTo-Json -Depth 6 | Set-Content "$StateDirectory\before.json"
        New-NetIPAddress -IPAddress $target4 -PrefixLength 24 -InterfaceIndex $index -PolicyStore ActiveStore -SkipAsSource $true | Out-Null
        New-NetIPAddress -IPAddress $target6 -PrefixLength 64 -InterfaceIndex $index -PolicyStore ActiveStore -SkipAsSource $true | Out-Null
        for ($i=0; $i -lt 100; $i++) {
            $states = @(Get-NetIPAddress -InterfaceIndex $index | Where-Object { $_.IPAddress -in @($target4,$target6) } | ForEach-Object AddressState)
            if (($states | Where-Object { $_ -eq 'Duplicate' }).Count) { throw 'Duplicate-address detection failed.' }
            if ($states.Count -eq 2 -and -not ($states | Where-Object { $_ -ne 'Preferred' })) { break }
            Start-Sleep -Milliseconds 100
        }
        foreach ($route in $routes) {
            New-NetRoute -DestinationPrefix $route.Prefix -NextHop $route.NextHop -InterfaceIndex $index -PolicyStore ActiveStore | Out-Null
        }
    }
    'Teardown' {
        $saved = Get-Content "$StateDirectory\before.json" -Raw | ConvertFrom-Json
        $errors = @()
        foreach ($route in $routes) {
            try { Get-NetRoute -DestinationPrefix $route.Prefix -NextHop $route.NextHop -InterfaceIndex $index -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false } catch { $errors += $_.Exception.Message }
        }
        foreach ($ip in @($target4,$target6)) {
            try { Get-NetIPAddress -IPAddress $ip -InterfaceIndex $index -ErrorAction SilentlyContinue |
                Remove-NetIPAddress -Confirm:$false } catch { $errors += $_.Exception.Message }
        }
        try { Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -Dhcp $saved.dhcp6 } catch { $errors += $_.Exception.Message }
        if ($errors.Count) { throw ('Routed teardown failed: ' + ($errors -join '; ')) }
        Get-State | ConvertTo-Json -Depth 6 | Set-Content "$StateDirectory\after.json"
    }
    'SetSackOpts' {
        if (Get-ItemProperty -Path $parameters -Name SackOpts -ErrorAction SilentlyContinue) { throw 'SackOpts already present.' }
        New-ItemProperty -Path $parameters -Name SackOpts -PropertyType DWord -Value 0 | Out-Null
        @{changed_utc = [DateTime]::UtcNow.ToString('o'); value = 0} | ConvertTo-Json | Set-Content "C:\nyxr-hz66-sackopts-set.json"
    }
    'ClearSackOpts' {
        Remove-ItemProperty -Path $parameters -Name SackOpts
        @{changed_utc = [DateTime]::UtcNow.ToString('o'); value = $null} | ConvertTo-Json | Set-Content "C:\nyxr-hz66-sackopts-cleared.json"
    }
}
Get-State | ConvertTo-Json -Depth 6 -Compress
