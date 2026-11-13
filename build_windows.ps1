param(
    [string]$Python = "$PSScriptRoot\.venv\Scripts\python.exe",
    [string]$AdbDirectory = '',
    [string]$NativeArtifacts = "$PSScriptRoot\native\build\artifacts",
    [string]$Destination = "$PSScriptRoot\dist"
)
$ErrorActionPreference = 'Stop'
$profile = Join-Path $PSScriptRoot 'profiles\pubgmhd-1.39.13-arm64.json'
$requiredNative = @('libue4trace.so', 'native-manifest.json')
$licenseDirectory = Join-Path $PSScriptRoot 'licenses'
foreach ($name in @('Dobby-Apache-2.0.txt', 'nlohmann-json-MIT.txt')) {
    if (-not (Test-Path -LiteralPath (Join-Path $licenseDirectory $name) -PathType Leaf)) {
        throw "Missing required third-party license: licenses/$name"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'DISCLAIMER.md') -PathType Leaf)) {
    throw 'Missing required DISCLAIMER.md'
}
foreach ($name in $requiredNative) {
    $source = Join-Path $NativeArtifacts $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing native artifact: $source. Build the collector first or supply -NativeArtifacts."
    }
}
if (-not (Test-Path -LiteralPath $profile -PathType Leaf)) {
    throw "Missing version profile: $profile"
}
$adbFiles = @('adb.exe', 'AdbWinApi.dll', 'AdbWinUsbApi.dll')
if ($AdbDirectory) {
    foreach ($name in $adbFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $AdbDirectory $name) -PathType Leaf)) {
            throw "-AdbDirectory must contain $name. Omit this parameter to select ADB in the UI."
        }
    }
}
$Python = (Get-Command $Python -ErrorAction Stop).Source
$pythonBase = (& $Python -c 'import sys; print(sys.base_prefix)').Trim()
if ($LASTEXITCODE -ne 0 -or -not $pythonBase) { throw 'Unable to inspect the selected Python interpreter.' }
$originalBuildPath = $env:PATH
# Keep unrelated SDK DLLs (such as Poppler ICU) out of dependency resolution.
$env:PATH = @((Split-Path $Python), $pythonBase, "$pythonBase\DLLs", "$env:SystemRoot\System32", $env:SystemRoot) -join ';'
try {
    & $Python -m PyInstaller --noconfirm --clean --onedir --windowed --name UE4Trace `
        --distpath $Destination --workpath "$PSScriptRoot\packaging-build" --specpath $PSScriptRoot `
        --paths $PSScriptRoot --exclude-module matplotlib --exclude-module numpy --exclude-module pandas `
        --exclude-module PySide6.QtWebEngineCore --exclude-module PySide6.QtWebEngineWidgets `
        --exclude-module PySide6.QtQml --exclude-module PySide6.QtQuick `
        "$PSScriptRoot\launcher.py"
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
} finally {
    $env:PATH = $originalBuildPath
}
$app = Join-Path $Destination 'UE4Trace'
$assets = Join-Path $app 'assets'
New-Item -ItemType Directory -Force -Path $assets | Out-Null
# Explicit allowlist: never copy an arbitrary development assets directory.
foreach ($name in $requiredNative) {
    Copy-Item -LiteralPath (Join-Path $NativeArtifacts $name) -Destination (Join-Path $assets $name) -Force
}
Copy-Item -LiteralPath $profile -Destination $assets -Force
$loader = Join-Path $NativeArtifacts 'inject'
if (Test-Path -LiteralPath $loader -PathType Leaf) {
    Copy-Item -LiteralPath $loader -Destination (Join-Path $assets 'inject') -Force
    Write-Output 'Included the caller-supplied loader; verify its license before redistributing.'
} else {
    Write-Output 'No loader bundled. Connect to an observer loaded by your own app or supply a licensed loader.'
}
if ($AdbDirectory) {
    $adbOutput = Join-Path $assets 'adb'
    New-Item -ItemType Directory -Force -Path $adbOutput | Out-Null
    foreach ($name in $adbFiles) {
        Copy-Item -LiteralPath (Join-Path $AdbDirectory $name) -Destination (Join-Path $adbOutput $name) -Force
    }
}
Copy-Item -LiteralPath $licenseDirectory -Destination $app -Recurse -Force
foreach ($name in @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'DISCLAIMER.md')) {
    $document = Join-Path $PSScriptRoot $name
    if (Test-Path -LiteralPath $document -PathType Leaf) {
        Copy-Item -LiteralPath $document -Destination $app -Force
    }
}
Write-Output "Built $app\UE4Trace.exe"
