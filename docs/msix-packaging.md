# MSIX packaging and Microsoft Store distribution

## Why this is on the table

Every PATANYX binary is unsigned, and SmartScreen blocks unsigned executables
on reputation that resets with every build. As of 2026 the Microsoft Store
charges nothing to publish — the company fee was dropped in May 2026 — and
**Microsoft re-signs submitted MSIX packages with their own certificate after
certification**. So the Store solves the first-install problem for free, with no
certificate to buy, and — unlike SignPath — **no requirement to open-source
anything**.

That does not make it strictly better. It costs the self-updater.

## The conflict, stated first because it decides the shape of everything else

`updater::installer::swap_and_relaunch` renames the running executable to
`.old` and writes new bytes at the real path. MSIX packages install to a
read-only location and are updated only through the Store. **That code cannot
run inside a package.**

So a packaged PATANYX is not a variant of the current one with extra metadata.
It is a build with a different update story, and the UI has to say so. An
Updates panel offering a button that cannot work is exactly the "renders and
does nothing" defect this project keeps writing gates against.

Consequences that follow:

- Store users get updates on Microsoft's timing, after certification review.
- The signed Ed25519 update channel keeps running for direct-download users and
  is simply absent for packaged ones.
- The blocklist refresh is unaffected — it downloads data, not a binary, and
  writes to app storage. It must keep working in both.

## Detecting that we are packaged

`GetCurrentPackageFullName` returns `APPMODEL_ERROR_NO_PACKAGE` (15700) when the
process has no package identity, and success otherwise. That is the canonical
check and needs no manifest reading, no path sniffing and no build-time flag —
which matters, because the same binary is what gets packaged.

**Verified 2026-07-28:** the API is not reachable with the current dependency
declaration. `windows = "0.61"` pulls default features only, and the module is
compiled out. The whole enablement is one feature:

```toml
windows = { version = "0.61", features = ["Win32_Storage_Packaging_Appx"] }
```

With that, the probe compiles for `x86_64-pc-windows-msvc`. Shape of the check:

```rust
/// True when this process runs from an MSIX package.
///
/// Runtime, not compile-time, and deliberately: the SAME binary is what gets
/// packaged, so a cargo feature would mean shipping two artifacts that differ
/// in a way no test could tell apart.
pub fn is_packaged() -> bool {
    let mut len: u32 = 0;
    // Called with a null buffer purely to read back the required length; the
    // return code is the answer and the name is not wanted.
    let rc = unsafe { GetCurrentPackageFullName(&mut len, None) };
    rc != APPMODEL_ERROR_NO_PACKAGE
}
```

Cache it in a `OnceLock`. Package identity cannot change while the process
lives, and this is consulted on every Updates render.

## What changes behind that flag

| Site                                                   | Unpackaged       | Packaged                                                     |
| ------------------------------------------------------ | ---------------- | ------------------------------------------------------------ |
| `updater::check_in_background`                         | runs on schedule | **not scheduled**                                            |
| `update_check` / `update_install` / `update_apply` IPC | as now           | refuse with a distinct code                                  |
| Updates panel                                          | current UI       | states that updates arrive through the Store, with no button |
| `schedule::UPDATE_EVERY`                               | 6h               | disabled                                                     |
| `schedule::BLOCKLIST_EVERY`                            | 1h               | **unchanged — still runs**                                   |

The IPC arms must refuse with their own error code rather than silently
succeeding. A packaged build whose update check quietly returned "up to date"
would be lying in the one place a user goes to check.

## Filesystem, which needs verifying rather than assuming

MSIX virtualises writes. `%APPDATA%` lands under
`%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Roaming`, transparently.
That _should_ mean the vault, profile and store all work unmodified — but
"should" is what this project keeps getting caught by, so each is a checklist
item, not an assumption:

- `Vault::default_path()` → `%APPDATA%\patanyx\vault.rbv`
- `browsing_profile_dir()` → sibling of the vault; WebView2's user-data folder
- `blocklist::store_dir()` → derived from `updater::data_dir()`

`data_dir()` on Windows has no `%APPDATA%` arm at all: it checks
`PATANYX_DATA_DIR`, then falls through to `std::env::temp_dir()`. So the
refreshed blocklist currently lives in **temp** on Windows, packaged or not.
That is a pre-existing bug, it is not caused by MSIX, and it should be fixed
before packaging rather than inherited into it.

**A migration question with a real cost:** an existing direct-install user who
switches to the Store version does not see their old vault, because the
packaged app reads a redirected `%APPDATA%`. They would appear to have lost
every credential. Either the packaged build reads the unpackaged location
explicitly, or the Store listing says plainly that it is a separate install and
tells them to export first. Silently starting empty is not an option.

## Packaging steps

1. Add the `Win32_Storage_Packaging_Appx` feature and `is_packaged()`.
2. Gate the updater and its panel on it.
3. Fix `data_dir()` to use `%APPDATA%` on Windows instead of temp.
4. Write `AppxManifest.xml` declaring `windows.fullTrustApplication` — the
   desktop-bridge entry point for a plain Win32 binary.
5. Package with `makeappx pack`, from a layout containing the exe, the OCR
   models, and the assets.
6. Sign locally with a test certificate purely to install and test. The Store
   re-signs; this signature is for the dev loop only and never ships.
7. Test packaged: vault opens, WebView2 profile is writable, blocklist refresh
   works, Updates panel says the right thing, freeze and DNS still behave.
8. Submit. Certification takes days to weeks.

## Judgement

Worth doing as an **additional** channel, not a replacement. It fixes
first-install for free without open-sourcing, which is the one thing actually
blocking distribution today.

Keep direct download first-class: it serves Linux, it keeps the self-updater,
and Store installs mean Microsoft knows who installed a privacy browser — which
part of this audience will care about, even though it is voluntary and
per-user.
