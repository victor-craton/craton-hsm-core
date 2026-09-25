# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# sign-integrity.ps1
# Signs a Craton HSM binary with Ed25519 and writes a .sig sidecar file.
#
# Usage:
#   .\tools\sign-integrity.ps1 [-LibPath <path>] [-PrivKeyPath <path>]
#
# If -LibPath is not specified, defaults to:
#   target\release\craton_hsm.dll (Windows)
#
# Private key is loaded from (in order):
#   1. -PrivKeyPath argument
#   2. CRATON_HSM_SIGNING_KEY environment variable
#   3. ~\.craton_hsm\integrity-signing-key.pem
#
# An encrypted key makes openssl prompt for its passphrase; for unattended
# signing set CRATON_HSM_SIGNING_KEY_PASS_FILE to a file (owner-only ACL)
# containing the passphrase.
#
# The .sig file is written next to the library with the extension replaced
# (craton_hsm.dll -> craton_hsm.sig), which is where the module looks for it.

param(
    [string]$LibPath,
    [string]$PrivKeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-OpenSsl([string[]]$Arguments) {
    & openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "openssl $($Arguments[0]) failed (exit $LASTEXITCODE); see the openssl output above."
    }
}

function Set-OwnerOnlyAcl([string]$Path) {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if (-not $LibPath) {
    $LibPath = "target\release\craton_hsm.dll"
}
if (-not (Test-Path -LiteralPath $LibPath -PathType Leaf)) {
    throw "Library not found at $LibPath. Build first: cargo build --release --lib"
}

if (-not $PrivKeyPath -and $env:CRATON_HSM_SIGNING_KEY) {
    $PrivKeyPath = $env:CRATON_HSM_SIGNING_KEY
}
if (-not $PrivKeyPath) {
    $PrivKeyPath = Join-Path $env:USERPROFILE ".craton_hsm\integrity-signing-key.pem"
}
if (-not (Test-Path -LiteralPath $PrivKeyPath -PathType Leaf)) {
    throw "Ed25519 private key not found at $PrivKeyPath. Generate one with: .\tools\generate-integrity-keypair.ps1"
}

$passArgs = @()
if ($env:CRATON_HSM_SIGNING_KEY_PASS_FILE) {
    $passArgs = @('-passin', "file:$($env:CRATON_HSM_SIGNING_KEY_PASS_FILE)")
}

$resolvedLib = (Resolve-Path -LiteralPath $LibPath).Path

# Private scratch directory with a random name and an owner-only ACL.
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("craton-sign-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work | Out-Null
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    Set-OwnerOnlyAcl $work
    $digestFile = Join-Path $work "digest.bin"
    $sigFile = Join-Path $work "digest.sig"
    $pubPem = Join-Path $work "pub.pem"

    # SHA-256 of the binary (streamed, not loaded into memory at once).
    $stream = [System.IO.File]::OpenRead($resolvedLib)
    try { $hashBytes = $sha256.ComputeHash($stream) } finally { $stream.Dispose() }
    $hashHex = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    [System.IO.File]::WriteAllBytes($digestFile, $hashBytes)

    Invoke-OpenSsl (@('pkeyutl', '-sign', '-inkey', $PrivKeyPath) + $passArgs + @('-rawin', '-in', $digestFile, '-out', $sigFile))
    if (-not (Test-Path -LiteralPath $sigFile) -or (Get-Item -LiteralPath $sigFile).Length -eq 0) {
        throw "Signing produced no signature."
    }

    # Verify before publishing.
    Invoke-OpenSsl (@('pkey', '-in', $PrivKeyPath) + $passArgs + @('-pubout', '-out', $pubPem))
    Invoke-OpenSsl @('pkeyutl', '-verify', '-pubin', '-inkey', $pubPem, '-rawin', '-in', $digestFile, '-sigfile', $sigFile)

    $sigBytes = [System.IO.File]::ReadAllBytes($sigFile)
    $sigHex = ($sigBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    if ($sigHex.Length -ne 128) {
        throw "Unexpected signature length ($($sigHex.Length) hex chars, expected 128)."
    }

    # Sidecar next to the library (mirrors Path::with_extension("sig")).
    $sigPath = [System.IO.Path]::ChangeExtension($resolvedLib, "sig")
    [System.IO.File]::WriteAllText($sigPath, $sigHex, [System.Text.Encoding]::ASCII)

    Write-Host "Signed:      $resolvedLib"
    Write-Host "Signature:   $sigPath"
    Write-Host "Binary size: $((Get-Item -LiteralPath $resolvedLib).Length) bytes"
    Write-Host "SHA-256:     $hashHex"
}
finally {
    $sha256.Dispose()
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
