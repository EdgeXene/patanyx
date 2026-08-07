# PATANYX smoke test — Windows counterpart to scripts/smoke.sh.
#
# Points the vault at a throwaway directory via PATANYX_DATA_DIR (the
# override hook honored by Vault::default_path on Windows) and runs the
# binary with --smoke-test, which drives the real IPC dispatch surface and
# prints SMOKE OK / SMOKE FAIL.
#
# Note: there is no xvfb equivalent on Windows and WebView2 must
# create a real HWND, so this requires an interactive window station. Expect
# it to work on a desktop session and on CI agents running in one (GitHub's
# windows-latest runners generally do), but NOT from a session-0 service or
# a headless container. The WebView2 Evergreen Runtime must also be
# installed (present on Windows 11 and most patched Windows 10 machines).

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$smokeDir = Join-Path $env:TEMP ("patanyx-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $smokeDir | Out-Null

$previousDataDir = $env:PATANYX_DATA_DIR
$env:PATANYX_DATA_DIR = $smokeDir
$code = 1
try {
    cargo build --manifest-path (Join-Path $repoRoot "Cargo.toml")
    if ($LASTEXITCODE -ne 0) {
        $code = $LASTEXITCODE
    } else {
        & (Join-Path $repoRoot "target\debug\patanyx.exe") --smoke-test
        $code = $LASTEXITCODE
    }
} finally {
    $env:PATANYX_DATA_DIR = $previousDataDir
    Remove-Item -Recurse -Force $smokeDir -ErrorAction SilentlyContinue
}
exit $code
