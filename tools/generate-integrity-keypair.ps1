# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# generate-integrity-keypair.ps1
# Generates the Ed25519 keypair used to sign Craton HSM binaries
# (see tools\sign-integrity.ps1 and src\crypto\integrity.rs).
#
# Usage:
#   .\tools\generate-integrity-keypair.ps1 [-OutputDir <path>] [-NoEncrypt]
#
#   -OutputDir  Directory for integrity-signing-key.pem
#               (default: %USERPROFILE%\.craton_hsm). A new directory gets an
#               owner-only ACL; an existing directory must not grant access to
#               anyone but the current user, SYSTEM and Administrators.
#   -NoEncrypt  Store the private key unencrypted (NOT recommended). By default
#               the PEM is encrypted with AES-256 under a passphrase that
#               openssl prompts for, or that is read from the file named by
#               $env:CRATON_HSM_SIGNING_KEY_PASS_FILE.
#
# Output: the build variable CRATON_HSM_INTEGRITY_PUBLIC_KEY=<64 hex chars>.
#
# Requires: OpenSSL 3 on PATH. The private key must NEVER be committed to VCS.

param(
    [string]$OutputDir,
    [switch]$NoEncrypt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$allowedSids = @($currentSid.Value, 'S-1-5-18', 'S-1-5-32-544')  # user, SYSTEM, Administrators

function Set-OwnerOnlyAcl([string]$Path, [bool]$IsDirectory) {
    # A fresh security descriptor replaces ALL existing ACEs (explicit and
    # inherited), unlike icacls /grant:r which keeps other explicit ACEs.
    if ($IsDirectory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-PrivateAcl([string]$Path) {
    foreach ($ace in (Get-Acl -LiteralPath $Path).Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try {
            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $ace.IdentityReference.Value
        }
        if ($allowedSids -notcontains $sid) {
            throw "$Path grants access to $($ace.IdentityReference); use a private directory for the signing key."
        }
    }
}

function Invoke-OpenSsl([string[]]$Arguments) {
    & openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "openssl $($Arguments[0]) failed (exit $LASTEXITCODE). Ensure OpenSSL 3 is on PATH."
    }
}

if (-not $OutputDir) {
    $OutputDir = Join-Path $env:USERPROFILE ".craton_hsm"
}

if (Test-Path -LiteralPath $OutputDir) {
    $item = Get-Item -LiteralPath $OutputDir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "$OutputDir exists and is not a plain directory."
    }
    # Never change the ACL of a directory this script did not create.
    Assert-PrivateAcl $OutputDir
} else {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Set-OwnerOnlyAcl $OutputDir $true
}

if (Get-Command git -ErrorAction SilentlyContinue) {
    & git -C $OutputDir rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -eq 0) {
        throw "$OutputDir is inside a git work tree; refusing to create a signing key there."
    }
    $global:LASTEXITCODE = 0
}

$privKeyPath = Join-Path $OutputDir "integrity-signing-key.pem"
$passArgs = @()
if ($env:CRATON_HSM_SIGNING_KEY_PASS_FILE) {
    $passArgs = @('-passin', "file:$($env:CRATON_HSM_SIGNING_KEY_PASS_FILE)")
}

if (Test-Path -LiteralPath $privKeyPath) {
    Write-Host "NOTE: Private key already exists at $privKeyPath (not regenerated)."
    Write-Host "      To regenerate, move it away first."
} else {
    # Create the file with an owner-only ACL before any key bytes are written.
    New-Item -ItemType File -Path $privKeyPath | Out-Null
    Set-OwnerOnlyAcl $privKeyPath $false
    $genArgs = @('genpkey', '-algorithm', 'Ed25519', '-out', $privKeyPath)
    if (-not $NoEncrypt) {
        $genArgs += '-aes-256-cbc'
        if ($env:CRATON_HSM_SIGNING_KEY_PASS_FILE) {
            $genArgs += @('-pass', "file:$($env:CRATON_HSM_SIGNING_KEY_PASS_FILE)")
        } else {
            Write-Host "Generating an encrypted Ed25519 key; openssl will prompt for a passphrase."
        }
    } else {
        Write-Warning "Generating an UNENCRYPTED private key (-NoEncrypt)."
    }
    try {
        Invoke-OpenSsl $genArgs
    } catch {
        Remove-Item -LiteralPath $privKeyPath -Force -ErrorAction SilentlyContinue
        throw
    }
    Write-Host "Generated private key: $privKeyPath"
}

# Private scratch directory for the public key and self-check.
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("craton-keygen-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Set-OwnerOnlyAcl $work $true
    $pubPem = Join-Path $work "pub.pem"
    $pubDer = Join-Path $work "pub.der"
    Invoke-OpenSsl (@('pkey', '-in', $privKeyPath) + $passArgs + @('-pubout', '-out', $pubPem))
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $pubPem, '-outform', 'DER', '-out', $pubDer)

    # DER is read as bytes from a file, never through the text pipeline.
    $derBytes = [System.IO.File]::ReadAllBytes($pubDer)
    if ($derBytes.Length -ne 44) {
        throw "Unexpected Ed25519 SubjectPublicKeyInfo length ($($derBytes.Length) bytes)."
    }
    $pubKeyHex = ($derBytes[12..43] | ForEach-Object { $_.ToString("x2") }) -join ""

    # Self-check: sign and verify a test message.
    $msg = Join-Path $work "msg"
    $sig = Join-Path $work "msg.sig"
    [System.IO.File]::WriteAllBytes($msg, [System.Text.Encoding]::ASCII.GetBytes("craton-hsm integrity self-test"))
    Invoke-OpenSsl (@('pkeyutl', '-sign', '-inkey', $privKeyPath) + $passArgs + @('-rawin', '-in', $msg, '-out', $sig))
    Invoke-OpenSsl @('pkeyutl', '-verify', '-pubin', '-inkey', $pubPem, '-rawin', '-in', $msg, '-sigfile', $sig)
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "=== Public key (hex) ==="
Write-Host $pubKeyHex
Write-Host ""
Write-Host "=== Build the library with the public key embedded ==="
Write-Host "`$env:CRATON_HSM_INTEGRITY_PUBLIC_KEY = '$pubKeyHex'; cargo build --release --lib"
Write-Host ""
Write-Host "=== SECURITY ==="
Write-Host "Private key: $privKeyPath"
Write-Host "  - NEVER commit this to version control"
Write-Host "  - Prefer an HSM/KMS for release signing; keep this file encrypted"
Write-Host "  - Back up securely - losing it requires re-signing all binaries"
