# Reach 项目 MSVC 编译环境初始化
# 用法：. .\env.ps1

$msvc = "X:\Visual Studio 2022\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
$sdkRoot = "X:\Visual Studio 2022\VC\Tools\MSVC\14.44.35207"

if (Test-Path $msvc) {
    $env:PATH = "$msvc;$env:PATH"
}

# 排除 MinGW 干扰
$parts = $env:PATH -split ";"
$filtered = $parts | Where-Object { $_ -notmatch "mingw" }
$env:PATH = $filtered -join ";"

# 确保 cargo bin 在 PATH
$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (Test-Path $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}

# Windows SDK
$sdkInc = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Include" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
$sdkLib = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Lib" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1

if ($sdkInc -and $sdkLib) {
    $env:INCLUDE = "$sdkRoot\include;$($sdkInc.FullName)\ucrt;$($sdkInc.FullName)\um;$($sdkInc.FullName)\shared"
    $env:LIB = "$sdkRoot\lib\x64;$($sdkLib.FullName)\ucrt\x64;$($sdkLib.FullName)\um\x64"
}

Write-Host "Reach MSVC 环境就绪" -ForegroundColor Green
