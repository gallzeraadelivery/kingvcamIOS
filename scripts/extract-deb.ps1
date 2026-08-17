#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = Join-Path $scriptDir "extract-deb.py"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3 nao encontrado no PATH."
    exit 1
}

& python $py @args
exit $LASTEXITCODE
