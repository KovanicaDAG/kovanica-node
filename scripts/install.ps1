# One-shot KovanicaDAG node install on Windows — no git clone.
#   irm https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.ps1 | iex
# Or: powershell -ExecutionPolicy Bypass -File install.ps1
$ErrorActionPreference = "Stop"
$HomeDir = if ($env:KOVANICA_HOME) { $env:KOVANICA_HOME } else { Join-Path $env:USERPROFILE "kovanica-node" }
$Seed = if ($env:KOVANICA_PEERS) { $env:KOVANICA_PEERS } else { "seed.kovanica.online:9000" }

function Need-Cmd($name) { Get-Command $name -ErrorAction SilentlyContinue }

if (-not (Need-Cmd cargo) -or -not (Need-Cmd rustc)) {
  Write-Host "Installing rustup…"
  $ru = Join-Path $env:TEMP "rustup-init.exe"
  Invoke-WebRequest -UseBasicParsing -Uri "https://win.rustup.rs/x86_64" -OutFile $ru
  & $ru -y --default-toolchain stable
  $env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
}

$zip = Join-Path $env:TEMP "kovanica-node-main.zip"
Write-Host "Downloading kovanica-node main (zip, no git)…"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/KovanicaDAG/kovanica-node/archive/refs/heads/main.zip" -OutFile $zip
$extract = Join-Path $env:TEMP "kovanica-node-src"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $zip -DestinationPath $extract
$src = Get-ChildItem $extract -Directory | Select-Object -First 1

New-Item -ItemType Directory -Force -Path (Join-Path $HomeDir "bin") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $HomeDir "data") | Out-Null
Push-Location $src.FullName
cargo build --release -p kovanica-node
Pop-Location
$exe = Join-Path $src.FullName "target\release\kovanica-node.exe"
Copy-Item $exe (Join-Path $HomeDir "bin\kovanica-node.exe") -Force

$run = Join-Path $HomeDir "run.cmd"
@"
@echo off
set KOVANICA_LISTEN=0.0.0.0:9000
set KOVANICA_PEERS=$Seed
set KOVANICA_MINE=0
set KOVANICA_MINE_SECS=120
set KOVANICA_FAUCET=0
set KOVANICA_POW=1
set KOVANICA_ALLOW_RESET=0
set KOVANICA_DATA=$HomeDir\data
"$HomeDir\bin\kovanica-node.exe" explorer 127.0.0.1:8080
"@ | Set-Content -Encoding ASCII $run

Write-Host "binary: $HomeDir\bin\kovanica-node.exe"
Write-Host "start:  $run"
Write-Host "check:  curl http://127.0.0.1:8080/api/head"
