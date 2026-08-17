#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& python (Join-Path $scriptDir "rebrand-pack.py") @args
exit $LASTEXITCODE
