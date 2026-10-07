param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$guiDir = Join-Path $repoRoot 'go/cmd/scanner-gui'
$outputDir = Join-Path $repoRoot 'build/gui/windows-amd64'

if ($env:OS -ne 'Windows_NT') {
    throw 'Use bash scripts/build-gui.sh on macOS or Linux.'
}
if (-not (Get-Command wails -ErrorAction SilentlyContinue)) {
    throw 'Install Wails first: go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0'
}

Push-Location (Join-Path $repoRoot 'go')
try {
    & go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed.' }
} finally { Pop-Location }

Push-Location $guiDir
try {
    & wails build -platform windows/amd64 -trimpath -ldflags '-s -w' -skipbindings
    if ($LASTEXITCODE -ne 0) { throw 'Windows GUI build failed.' }
} finally { Pop-Location }

New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$executable = Join-Path $guiDir 'build/bin/WhiteDNS-Scanner.exe'
$archive = Join-Path $outputDir 'WhiteDNS-Scanner-windows-amd64.zip'
Compress-Archive -LiteralPath $executable,(Join-Path $repoRoot 'README.md') -DestinationPath $archive -Force
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$archive.sha256", "$hash  $([IO.Path]::GetFileName($archive))`n", [Text.UTF8Encoding]::new($false))
Write-Host "Built $archive"
