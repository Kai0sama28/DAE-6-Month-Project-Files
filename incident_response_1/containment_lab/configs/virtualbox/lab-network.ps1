param(
    [string]$InterfaceName = "",
    [switch]$Apply
)

$ErrorActionPreference = "Stop"

$HostIp = "192.168.56.1"
$Mask = "255.255.255.0"

$Candidates = @(
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "VBoxManage.exe",
    "VBoxManage"
)

$VBox = $null
foreach ($Candidate in $Candidates) {
    if (Test-Path $Candidate) {
        $VBox = $Candidate
        break
    }
    $Resolved = Get-Command $Candidate -ErrorAction SilentlyContinue
    if ($Resolved) {
        $VBox = $Resolved.Source
        break
    }
}

if (-not $VBox) {
    throw "VBoxManage was not found. Install VirtualBox or pass its full path."
}

$HostOnly = @(& $VBox list hostonlyifs)
$HostOnlyText = $HostOnly -join "`n"
$Names = @([regex]::Matches($HostOnlyText, "(?m)^Name:\s+(.+?)\s*$") | ForEach-Object { $_.Groups[1].Value.Trim() })

$VBoxIf = "vboxnet0"
if ($InterfaceName) {
    $VBoxIf = $InterfaceName
}
elseif ($Names -contains "vboxnet0") {
    $VBoxIf = "vboxnet0"
}
else {
    $Preferred = [regex]::Match($HostOnlyText, "(?ms)^Name:\s+(.+?)\s*$.*?^IPAddress:\s+192\.168\.56\.1\s*$")
    if ($Preferred.Success) {
        $VBoxIf = $Preferred.Groups[1].Value.Trim()
    }
    elseif ($Names.Count -gt 0) {
        $VBoxIf = $Names[0]
    }
}

$Exists = $Names -contains $VBoxIf

Write-Host "VBoxManage: $VBox"
Write-Host "Host-only interface: $VBoxIf"
Write-Host "Host address: $HostIp/$Mask"

if (-not $Apply) {
    Write-Host ""
    Write-Host "Detected host-only interfaces: $($Names -join ', ')"
    Write-Host "Dry run. Re-run with -Apply to create and configure the host-only network."
    if (-not $Exists) {
        Write-Host "& `"$VBox`" hostonlyif create"
        Write-Host "& `"$VBox`" hostonlyif ipconfig `"$VBoxIf`" --ip $HostIp --netmask $Mask"
    }
    else {
        Write-Host "& `"$VBox`" hostonlyif ipconfig `"$VBoxIf`" --ip $HostIp --netmask $Mask"
    }
    Write-Host "& `"$VBox`" dhcpserver remove --ifname `"$VBoxIf`""
    Write-Host "& `"$VBox`" list hostonlyifs"
    Write-Host ""
    Write-Host "Internal networks are created when the first VM adapter is attached:"
    Write-Host "  IR-LAB-CORE, IR-LAB-PROTECTED, IR-LAB-QUARANTINE"
    exit 0
}

if (-not $Exists) {
    $Created = & $VBox hostonlyif create
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create host-only interface."
    }
    $CreatedName = ($Created | Select-String -Pattern "Interface '([^']+)'" | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1)
    if ($CreatedName) {
        $VBoxIf = $CreatedName
    }
}

& $VBox hostonlyif ipconfig "$VBoxIf" --ip $HostIp --netmask $Mask
if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure $VBoxIf."
}

& $VBox dhcpserver remove --ifname "$VBoxIf" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "No DHCP server attached to $VBoxIf (expected)."
}

& $VBox list hostonlyifs
& $VBox list dhcpservers
