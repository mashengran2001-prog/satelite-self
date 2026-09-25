# Satelite 1.1.6 Release Build Script
# Run this in a normal PowerShell terminal (outside Claude Code) to avoid session timeout issues.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$defaultSigningKey = Join-Path $HOME ".satelite-updater\satelite.key"
Write-Host "Step 1/4: Building frontend..." -ForegroundColor Cyan
corepack pnpm run build
if ($LASTEXITCODE -ne 0) { throw "Frontend build failed" }

Write-Host "`nStep 2/4: Staging sing-box core..." -ForegroundColor Cyan
.\scripts\fetch-bundled-core-windows-amd64.ps1

# Verify core files (CI does this too)
$coreDir = "src-tauri\resources\bin\windows-amd64"
foreach ($f in @("sing-box.exe", "libcronet.dll", "version.txt")) {
    $path = Join-Path $coreDir $f
    if (-not (Test-Path $path)) {
        throw "$f missing after fetch — upstream release may no longer ship it"
    }
}

Write-Host "`nStep 3/4: Staging built-in rule sets..." -ForegroundColor Cyan
$sets = @(
    @{ Name = "system-geolocation-not-cn.srs"; Url = "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs" },
    @{ Name = "system-geoip-cn.srs";           Url = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs" },
    @{ Name = "system-geosite-cn.srs";         Url = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs" }
)
$ruleDir = "src-tauri\resources\rule-sets"
New-Item -ItemType Directory -Force -Path $ruleDir | Out-Null
foreach ($s in $sets) {
    $out = Join-Path $ruleDir $s.Name
    Write-Host "  Downloading $($s.Name)..."
    Invoke-WebRequest -Uri $s.Url -OutFile $out -UseBasicParsing
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $out).Path)
    $magic = if ($bytes.Length -ge 3) {
        [System.Text.Encoding]::ASCII.GetString($bytes, 0, 3)
    } else {
        ""
    }
    if ($magic -ne "SRS") { throw "$($s.Name) is not a binary SRS (bad URL or HTML error page)" }
}

Write-Host "`nStep 4/4: Building signed installer (this will take 15-20 minutes)..." -ForegroundColor Cyan
Write-Host "Compiling Rust dependencies and bundling NSIS installer..." -ForegroundColor Gray
corepack pnpm exec tauri build --bundles nsis --config src-tauri/tauri.singbox-windows.conf.json --config src-tauri/tauri.manual-updater-signing.conf.json

if ($LASTEXITCODE -eq 0) {
    $installer = "src-tauri\target\release\bundle\nsis\Satelite_1.1.6_x64-setup.exe"
    if (-not (Test-Path $defaultSigningKey)) {
        throw "Updater signing key not found: $defaultSigningKey"
    }
    # An empty password cannot be preserved as a Windows environment variable.
    # Pass it explicitly so Tauri does not wait forever for an interactive prompt.
    corepack pnpm exec tauri signer sign --private-key-path $defaultSigningKey --password= $installer
    if ($LASTEXITCODE -ne 0) { throw "Updater signing failed" }

    Write-Host "`nBuild complete!" -ForegroundColor Green
    Write-Host "Installer: $installer"
    Write-Host "Signature: $installer.sig"
} else {
    throw "Tauri build failed with exit code $LASTEXITCODE"
}
