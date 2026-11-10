# Reproducible Windows build, test, SDK consumer verification and ZIP packaging.
[CmdletBinding()]
param(
    [ValidateSet('release', 'debug', 'software', 'shared', 'asan', 'minimal')]
    [string]$Variant = 'release',
    [string]$BuildDirectory,
    [string]$Catch2Source,
    [string]$BenchmarkSource,
    [switch]$Offline,
    [switch]$Interop,
    [int]$Jobs = 8
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Jobs -lt 1) { throw 'Jobs must be positive.' }
$repository = Split-Path -Parent $PSScriptRoot
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $repository "build/delivery-$Variant" }
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
$logs = Join-Path $BuildDirectory 'logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$configuration = if ($Variant -eq 'debug') { 'Debug' } else { 'Release' }

function Invoke-Step([string]$Name, [string]$Program, [string[]]$Arguments) {
    $log = Join-Path $logs "delivery-$Variant-$Name.log"
    if (-not (Test-Path -LiteralPath $Program -PathType Leaf)) { throw "Missing program: $Program" }
    # Windows PowerShell wraps native stderr in ErrorRecord even for exit code 0.
    # Capture it as text, and decide success from the native exit code explicitly.
    $ErrorActionPreference = 'Continue'
    # Arguments are passed as an array; no command-string evaluation.
    & $Program @Arguments 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath $log | Out-Host
    $result = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    # Out-File appends without reopening the log for reading (unlike Add-Content).
    "Exit code: $result" | Out-File -LiteralPath $log -Append
    if ($result -ne 0) { throw "$Name failed ($result). See $log" }
}

# Resolve Visual Studio independently: cl can be on PATH without VSINSTALLDIR.
$vsPath = $env:VSINSTALLDIR
if (-not $vsPath) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio 2022 C++ build tools and Windows SDK.' }
    $vsPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) { throw 'No Visual Studio C++ toolchain found.' }
}
# Select x64 explicitly, even when a partial or different MSVC environment exists.
& {
    $devCmd = Join-Path $vsPath 'Common7/Tools/VsDevCmd.bat'
    $environmentLines = & $env:ComSpec /d /c ('call "' + $devCmd + '" -no_logo -arch=x64 -host_arch=x64 >nul && set')
    if ($LASTEXITCODE -ne 0) { throw 'MSVC environment setup failed.' }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
}
$ninja = Get-Command ninja.exe -ErrorAction SilentlyContinue
if ($ninja) { $ninjaPath = $ninja.Source }
else {
    $ninjaPath = Join-Path $vsPath 'Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe'
    if (-not (Test-Path -LiteralPath $ninjaPath)) { throw 'Ninja is required. Install Ninja or Visual Studio CMake tools.' }
}
$cmake = (Get-Command cmake.exe -ErrorAction Stop).Source
$ctest = Join-Path (Split-Path $cmake) 'ctest.exe'
$cpack = Join-Path (Split-Path $cmake) 'cpack.exe'
$configure = @('-S', $repository, '-B', $BuildDirectory, '-G', 'Ninja',
    "-DCMAKE_MAKE_PROGRAM=$ninjaPath", "-DCMAKE_BUILD_TYPE=$configuration",
    '-DSTREAMCIPHER_BUILD_TESTS=ON', '-DSTREAMCIPHER_BUILD_APPS=ON',
    '-DSTREAMCIPHER_BUILD_EXAMPLES=ON', '-DSTREAMCIPHER_BUILD_BENCHMARKS=ON',
    '-DSTREAMCIPHER_USE_AESNI=ON', '-DSTREAMCIPHER_USE_SIMD=ON',
    '-DBUILD_SHARED_LIBS=OFF', '-DSTREAMCIPHER_ENABLE_ASAN=OFF')
$configure += "-DSTREAMCIPHER_FETCH_DEPENDENCIES=$(if ($Offline) { 'OFF' } else { 'ON' })"
if ($Catch2Source) { $configure += "-DFETCHCONTENT_SOURCE_DIR_CATCH2=$([IO.Path]::GetFullPath($Catch2Source))" }
if ($BenchmarkSource) { $configure += "-DFETCHCONTENT_SOURCE_DIR_GOOGLE_BENCHMARK=$([IO.Path]::GetFullPath($BenchmarkSource))" }
switch ($Variant) {
    'software' { $configure += @('-DSTREAMCIPHER_USE_AESNI=OFF', '-DSTREAMCIPHER_USE_SIMD=OFF') }
    'shared' { $configure += '-DBUILD_SHARED_LIBS=ON' }
    'asan' { $configure += '-DSTREAMCIPHER_ENABLE_ASAN=ON' }
    'minimal' { $configure += @('-DSTREAMCIPHER_BUILD_TESTS=OFF', '-DSTREAMCIPHER_BUILD_APPS=OFF',
        '-DSTREAMCIPHER_BUILD_EXAMPLES=OFF', '-DSTREAMCIPHER_BUILD_BENCHMARKS=OFF', '-DSTREAMCIPHER_FETCH_DEPENDENCIES=OFF') }
}
Invoke-Step 'configure' $cmake $configure
Invoke-Step 'build' $cmake @('--build', $BuildDirectory, '--parallel', "$Jobs")
if ($Variant -eq 'minimal') { return }
Invoke-Step 'tests' $ctest @('--test-dir', $BuildDirectory, '--output-on-failure', '-j', "$Jobs")
if ($Interop) {
    Invoke-Step 'interop' (Get-Command python.exe -ErrorAction Stop).Source @(
        (Join-Path $repository 'tests/check_interop.py'), (Join-Path $BuildDirectory 'apps/scipher.exe'))
}

# Instrumented/debug builds are verification artifacts; release SDKs are distributable.
if ($Variant -in @('debug', 'asan')) { return }
$sdk = Join-Path $BuildDirectory 'sdk'
Invoke-Step 'install' $cmake @('--install', $BuildDirectory, '--prefix', $sdk)
# The installed executable is tested separately from the build-tree executable.
Invoke-Step 'installed-cli' (Get-Command python.exe -ErrorAction Stop).Source @(
    (Join-Path $repository 'tests/test_cli.py'), (Join-Path $sdk 'bin/scipher.exe'))
$consumer = Join-Path $BuildDirectory 'consumer'
Invoke-Step 'consumer-configure' $cmake @('-S', (Join-Path $repository 'tests/consumer'), '-B', $consumer,
    '-G', 'Ninja', "-DCMAKE_MAKE_PROGRAM=$ninjaPath", '-DCMAKE_BUILD_TYPE=Release',
    '-DCONSUME_INSTALLED=ON', "-DCMAKE_PREFIX_PATH=$sdk")
Invoke-Step 'consumer-build' $cmake @('--build', $consumer, '--parallel', "$Jobs")
# Consumers of a DLL must be able to locate its runtime binary.
$originalPath = $env:PATH
try {
    $env:PATH = (Join-Path $sdk 'bin') + ';' + $originalPath
    Invoke-Step 'consumer-tests' $ctest @('--test-dir', $consumer, '--output-on-failure')
} finally { $env:PATH = $originalPath }
Invoke-Step 'package' $cpack @('--config', (Join-Path $BuildDirectory 'CPackConfig.cmake'), '-B', $BuildDirectory)
$package = Get-ChildItem -LiteralPath $BuildDirectory -Filter 'streamcipher-*.zip' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $package) { throw 'CPack did not produce a ZIP archive.' }
$packageCheck = Join-Path $BuildDirectory ('package-check-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $package.FullName -DestinationPath $packageCheck
$packageRoot = @(Get-ChildItem -LiteralPath $packageCheck -Directory)
if ($packageRoot.Count -ne 1) { throw 'Unexpected ZIP layout.' }
$packageRoot = $packageRoot[0].FullName
Invoke-Step 'unpacked-cli' (Get-Command python.exe -ErrorAction Stop).Source @(
    (Join-Path $repository 'tests/test_cli.py'), (Join-Path $packageRoot 'bin/scipher.exe'))
$manualBuild = Join-Path $packageCheck 'manual-build'
Invoke-Step 'manual-configure' $cmake @('-S', (Join-Path $packageRoot 'share/doc/streamcipher/docs/examples'),
    '-B', $manualBuild, '-G', 'Ninja', "-DCMAKE_MAKE_PROGRAM=$ninjaPath", '-DCMAKE_BUILD_TYPE=Release',
    "-DCMAKE_PREFIX_PATH=$packageRoot")
Invoke-Step 'manual-build' $cmake @('--build', $manualBuild, '--parallel', "$Jobs")
$originalPath = $env:PATH
try {
    $env:PATH = (Join-Path $packageRoot 'bin') + ';' + $originalPath
    foreach ($example in @('memory_gcm', 'stream_modes', 'core_and_memory')) {
        Invoke-Step "example-$example" (Join-Path $manualBuild "$example.exe") @()
    }
    $demoInput = Join-Path $packageCheck 'input.txt'
    $demoEncrypted = Join-Path $packageCheck 'encrypted.bin'
    $demoRecovered = Join-Path $packageCheck 'recovered.txt'
    Set-Content -LiteralPath $demoInput -Value 'StreamCipher delivery example' -Encoding UTF8
    Invoke-Step 'example-file_gcm' (Join-Path $manualBuild 'file_gcm.exe') @($demoInput, $demoEncrypted, $demoRecovered)
    if ((Get-FileHash -LiteralPath $demoInput).Hash -ne (Get-FileHash -LiteralPath $demoRecovered).Hash) {
        throw 'Packaged file example round-trip mismatch.'
    }
} finally { $env:PATH = $originalPath }
Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256 |
    Format-List | Out-String | Set-Content -LiteralPath (Join-Path $logs "delivery-$Variant-package-sha256.log")
Write-Host "Completed: $BuildDirectory"
