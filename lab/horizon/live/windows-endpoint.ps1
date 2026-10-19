# Native Windows TCP fixture. Run in an elevated PowerShell console.
# No TCP feature is changed. The one temporary firewall rule is peer/address scoped.
param(
    [Parameter(Mandatory=$true)][string]$LocalAddress,
    [Parameter(Mandatory=$true)][string]$PeerAddress,
    [switch]$AddTemporaryIPv6,
    [string]$InterfaceIPv4,
    [switch]$StudyControl,
    [ValidateRange(60,21600)][int]$Seconds = 600
)
$ErrorActionPreference = 'Stop'
$local = [System.Net.IPAddress]::Parse($LocalAddress)
$peer = [System.Net.IPAddress]::Parse($PeerAddress)
if ($local.AddressFamily -ne $peer.AddressFamily) { throw 'Source/target address families must match.' }
$family = if ($local.AddressFamily -eq 'InterNetworkV6') { 'IPv6' } else { 'IPv4' }
foreach ($ip in @($local,$peer)) {
    $octets = $ip.GetAddressBytes()
    if ($family -eq 'IPv6') {
        if (($octets[0] -band 254) -ne 252 -or $ip.ScopeId -ne 0) { throw 'Use an operator-owned ULA virtual segment.' }
    } elseif (-not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168))) { throw 'Use an operator-owned RFC1918 virtual segment.' }
}
$LocalAddress = $local.ToString()
$PeerAddress = $peer.ToString()
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated console is required for the temporary scoped firewall rule.'
}
$address = @(Get-NetIPAddress -IPAddress $LocalAddress -AddressFamily $family -ErrorAction SilentlyContinue)
if ($AddTemporaryIPv6) {
    if ($family -ne 'IPv6' -or $address.Count -ne 0 -or -not $InterfaceIPv4) {
        throw 'Temporary IPv6 requires an unused ULA and an existing adapter IPv4 address.'
    }
    $selector = [System.Net.IPAddress]::Parse($InterfaceIPv4)
    $octets = $selector.GetAddressBytes()
    if ($selector.AddressFamily -ne 'InterNetwork' -or -not ($octets[0] -eq 10 -or
        ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168))) { throw 'Adapter selector must be RFC1918 IPv4.' }
    $adapterAddress = @(Get-NetIPAddress -IPAddress $InterfaceIPv4 -AddressFamily IPv4)
    if ($adapterAddress.Count -ne 1) { throw 'Adapter selector is not uniquely assigned.' }
    $interfaceIndex = $adapterAddress[0].InterfaceIndex
} else {
    if ($address.Count -ne 1) { throw 'Local address is not uniquely assigned.' }
    $interfaceIndex = $address[0].InterfaceIndex
}
$setupAddresses = @(Get-NetIPAddress -InterfaceIndex $interfaceIndex | Select-Object IPAddress,AddressFamily,PrefixLength,AddressState)
$setupRoutes = @(Get-NetRoute -InterfaceIndex $interfaceIndex | Select-Object DestinationPrefix,NextHop,RouteMetric)
$ipv6Settings = if ($family -eq 'IPv6') { Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv6 } else { $null }
$fixture = [guid]::NewGuid().ToString()
$ruleName = 'nyxr-hz66-' + $fixture
$controlRuleName = 'nyxr-hz66-control-' + $fixture
$blockRuleName = 'nyxr-hz66-block-' + $fixture
$listener = New-Object System.Net.Sockets.TcpListener($local,443)
$controlListener = if ($StudyControl) { New-Object System.Net.Sockets.TcpListener($local,8443) } else { $null }
$createdRule = $false
$createdControlRule = $false
$createdBlockRule = $false
$createdAddress = $false
$attemptedAddress = $false
function Get-Truth {
    $os = Get-CimInstance Win32_OperatingSystem
    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    $controlRule = Get-NetFirewallRule -Name $controlRuleName -ErrorAction SilentlyContinue
    $blockRule = Get-NetFirewallRule -Name $blockRuleName -ErrorAction SilentlyContinue
    $sackOpts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
        -Name SackOpts -ErrorAction SilentlyContinue
    [ordered]@{
        fixture = $fixture; utc = [DateTime]::UtcNow.ToString('o'); pid = $PID
        platform = 'Windows'; caption = $os.Caption; version = $os.Version
        build = $os.BuildNumber; architecture = $os.OSArchitecture
        last_boot_utc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        local_address = $LocalAddress; peer_address = $PeerAddress; port = 443
        temporary_address_created = $createdAddress
        setup_addresses_before = $setupAddresses; setup_routes_before = $setupRoutes
        ipv6_interface_before = $ipv6Settings | Select-Object InterfaceIndex,Dhcp,RouterDiscovery
        addresses = @(Get-NetIPAddress -InterfaceIndex $address.InterfaceIndex |
            Select-Object IPAddress,AddressFamily,PrefixLength,AddressState)
        routes = @(Get-NetRoute -InterfaceIndex $address.InterfaceIndex |
            Select-Object DestinationPrefix,NextHop,RouteMetric)
        adapter = Get-NetAdapter -InterfaceIndex $address.InterfaceIndex |
            Select-Object InterfaceDescription,MacAddress,Status,LinkSpeed
        tcp_settings = @(Get-NetTCPSetting | Select-Object SettingName,AutoTuningLevelLocal,
            CongestionProvider,EcnCapability,Timestamps)
        tcp_global = (netsh interface tcp show global | Out-String)
        sack_setting = 'Native Windows TCP; this helper does not change SACK'
        sackopts_registry_present = [bool]$sackOpts
        sackopts_registry_value = if ($sackOpts) { $sackOpts.SackOpts } else { $null }
        study_control = [bool]$StudyControl
        firewall_profiles = @(Get-NetFirewallProfile | Select-Object Name,Enabled,
            DefaultInboundAction,DefaultOutboundAction)
        fixture_rule_present = [bool]$rule
        fixture_rule = @($rule | Select-Object Name,Enabled,Direction,Action)
        fixture_addresses = @($rule | Get-NetFirewallAddressFilter |
            Select-Object LocalAddress,RemoteAddress)
        fixture_ports = @($rule | Get-NetFirewallPortFilter |
            Select-Object Protocol,LocalPort,RemotePort)
        control_rule_present = [bool]$controlRule
        control_rule = @($controlRule | Select-Object Name,Enabled,Direction,Action)
        control_addresses = @($controlRule | Get-NetFirewallAddressFilter |
            Select-Object LocalAddress,RemoteAddress)
        control_ports = @($controlRule | Get-NetFirewallPortFilter |
            Select-Object Protocol,LocalPort,RemotePort)
        block_rule_present = [bool]$blockRule
        block_rule = @($blockRule | Select-Object Name,Enabled,Direction,Action)
        block_addresses = @($blockRule | Get-NetFirewallAddressFilter |
            Select-Object LocalAddress,RemoteAddress)
        block_ports = @($blockRule | Get-NetFirewallPortFilter |
            Select-Object Protocol,LocalPort,RemotePort)
    }
}
try {
    if ($AddTemporaryIPv6) {
        $attemptedAddress = $true
        $address = New-NetIPAddress -IPAddress $LocalAddress -PrefixLength 64 -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -SkipAsSource $true
        $createdAddress = $true
        # Wait for duplicate-address detection before binding the listener.
        for ($i=0; $i -lt 100; $i++) {
            $address = Get-NetIPAddress -IPAddress $LocalAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv6
            if ($address.AddressState -eq 'Preferred') { break }
            if ($address.AddressState -eq 'Duplicate') { throw 'Temporary ULA failed duplicate-address detection.' }
            Start-Sleep -Milliseconds 100
        }
        if ($address.AddressState -ne 'Preferred') { throw 'Temporary ULA did not become ready.' }
    }
    # Bind first: never replace an existing listener on the chosen address/port.
    $listener.Start()
    if ($StudyControl) { $controlListener.Start() }
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound `
        -Action Allow -Protocol TCP -LocalAddress $LocalAddress -RemoteAddress $PeerAddress `
        -LocalPort 443 -Profile Any | Out-Null
    $createdRule = $true
    if ($StudyControl) {
        New-NetFirewallRule -Name $controlRuleName -DisplayName $controlRuleName -Direction Inbound `
            -Action Allow -Protocol TCP -LocalAddress $LocalAddress -RemoteAddress $PeerAddress `
            -LocalPort 8443 -Profile Any | Out-Null
        $createdControlRule = $true
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    Write-Host "HORIZON fixture $fixture listening on ${LocalAddress}:443 for $PeerAddress; expires in $Seconds seconds."
    if ($StudyControl) { Write-Host 'Fixed study controls listening on port 8443.' }
    Write-Host 'Leave this console open. Ctrl+C stops it and removes its rule.'
    while ([DateTime]::UtcNow -lt $deadline) {
        $commandListener = if ($StudyControl) { $controlListener } else { $listener }
        if (-not $commandListener.Pending()) {
            if ($StudyControl -and $listener.Pending()) { $listener.AcceptTcpClient().Dispose() }
            else { Start-Sleep -Milliseconds 25 }
            continue
        }
        $client = $commandListener.AcceptTcpClient()
        try {
            if (-not $client.Client.RemoteEndPoint.Address.Equals($peer)) { continue }
            $stream = $client.GetStream()
            $stream.ReadTimeout = 2000
            $stream.WriteTimeout = 2000
            $reader = New-Object IO.StreamReader($stream)
            # Only fixed telemetry/stop messages are accepted, never code or paths.
            $request = ''
            while ($request.Length -lt 16) {
                $character = $reader.Read()
                if ($character -lt 0 -or $character -eq 10) { break }
                $request += [char]$character
            }
            if ($request.Trim() -eq 'TRUTH') { $response = Get-Truth }
            elseif ($StudyControl -and $request.Trim() -eq 'BLOCK') {
                if (-not $createdBlockRule) {
                    New-NetFirewallRule -Name $blockRuleName -DisplayName $blockRuleName -Direction Inbound `
                        -Action Block -Protocol TCP -LocalAddress $LocalAddress -RemoteAddress $PeerAddress `
                        -LocalPort 443 -Profile Any | Out-Null
                    $createdBlockRule = $true
                }
                $response = Get-Truth
            }
            elseif ($StudyControl -and $request.Trim() -eq 'UNBLOCK') {
                if ($createdBlockRule) {
                    Remove-NetFirewallRule -Name $blockRuleName
                    $createdBlockRule = $false
                }
                $response = Get-Truth
            }
            elseif ($request.Trim() -eq 'STOP') {
                if ($createdBlockRule) {
                    Remove-NetFirewallRule -Name $blockRuleName
                    $createdBlockRule = $false
                }
                Remove-NetFirewallRule -Name $ruleName
                $createdRule = $false
                if ($createdControlRule) {
                    Remove-NetFirewallRule -Name $controlRuleName
                    $createdControlRule = $false
                }
                $response = Get-Truth
                $deadline = [DateTime]::UtcNow
            } else { continue }
            $bytes = [Text.Encoding]::UTF8.GetBytes(($response | ConvertTo-Json -Depth 8 -Compress) + "`n")
            $stream.Write($bytes,0,$bytes.Length)
        } catch [System.IO.IOException] {
            # Raw SYN baselines never send an application request.
        } finally { $client.Dispose() }
    }
} finally {
    $listener.Stop()
    if ($StudyControl) { $controlListener.Stop() }
    $cleanupErrors = @()
    if ($createdBlockRule) {
        try { Remove-NetFirewallRule -Name $blockRuleName } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($createdRule) {
        try { Remove-NetFirewallRule -Name $ruleName } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($createdControlRule) {
        try { Remove-NetFirewallRule -Name $controlRuleName } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($attemptedAddress) {
        try {
            $owned = @(Get-NetIPAddress -IPAddress $LocalAddress -InterfaceIndex $interfaceIndex -ErrorAction SilentlyContinue)
            if ($owned.Count -gt 0) { $owned | Remove-NetIPAddress -Confirm:$false }
        } catch { $cleanupErrors += $_.Exception.Message }
        # New-NetIPAddress can disable DHCP for this family; restore its prior state.
        try {
            Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv6 -Dhcp $ipv6Settings.Dhcp
        } catch { $cleanupErrors += $_.Exception.Message }
        $remaining = @(Get-NetIPAddress -IPAddress $LocalAddress -InterfaceIndex $interfaceIndex -ErrorAction SilentlyContinue)
        Write-Host "Temporary IPv6 address removed: $($remaining.Count -eq 0)"
        $restored = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv6
        Write-Host "IPv6 DHCP state restored: $($restored.Dhcp -eq $ipv6Settings.Dhcp)"
    }
    if ($cleanupErrors.Count -gt 0) { throw ('Fixture cleanup failed: ' + ($cleanupErrors -join '; ')) }
    Write-Host "HORIZON fixture stopped; temporary rule $ruleName removed."
}
