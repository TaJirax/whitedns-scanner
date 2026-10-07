param(
    [string]$Output = "$PSScriptRoot/../build/mobile/scanner.aar"
)
$ErrorActionPreference = 'Stop'
if (!$env:ANDROID_HOME -and $env:ANDROID_SDK_ROOT) { $env:ANDROID_HOME = $env:ANDROID_SDK_ROOT }
if (!$env:ANDROID_HOME) { throw 'Set ANDROID_HOME to your Android SDK.' }
$outputPath = [System.IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path (Split-Path $outputPath) -Force | Out-Null
Push-Location "$PSScriptRoot/../go"
try {
    go test ./engine ./mobile
    if ($LASTEXITCODE) { throw 'Scanner engine tests failed.' }
    go run golang.org/x/mobile/cmd/gomobile bind -target=android -androidapi 26 -o $outputPath ./mobile
    if ($LASTEXITCODE) { throw 'Android binding build failed.' }
} finally { Pop-Location }
