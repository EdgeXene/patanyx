//! Chrome's add-on actions. One worker job per window, explicit checks only.
//! Disk/network work stays off the event loop; completed bundles carry only
//! verified bytes. Teardown stays in addon_session and resumes on its events.
use crate::{
    addon_data,
    addon_delivery::{Cancellation, Credentials, DeliveryClient, DeliveryError, Refusal},
    addon_host::{self, ServedBundle},
    addon_install::{self, InstallError, InstallStore, InstalledSummary, ReleaseChoice},
    addon_session::{self, Reason, Then},
    state::AppState,
    UserEvent,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

/// The catalog is asked for when the Add-ons panel opens, and Rust decides
/// whether that becomes a request (plan P-4): never again for this long after
/// an answer ...
const CATALOG_AFTER_SUCCESS: Duration = Duration::from_secs(600);
/// ... and never again for this long after a failure, or for the server's
/// Retry-After when that is longer. The licence routes share one small budget
/// with activation.
const CATALOG_AFTER_FAILURE: Duration = Duration::from_secs(60);

/// Shown in Windows builds from 1.1.0. Linux builds keep it hidden until the
/// add-on window has been tested on a real Linux desktop, so the copy can say
/// Windows and mean it. A qualification build (`--features addon-launch`)
/// shows it on either platform, and says so.
pub(crate) const MANAGER_VISIBLE: bool = cfg!(any(windows, feature = "addon-launch"));

/// In a qualification build only; build-windows.sh and build-flatpak.sh
/// refuse a public build that carries it. Long enough that rustc stores it
/// whole (build-windows.sh explains why a short marker is not).
#[cfg(feature = "addon-launch")]
pub(crate) const LAUNCH_TEST_MARKER: &str = "ADD-ON LAUNCH TEST BUILD: the add-on manager is shown before its release";

#[cfg(feature = "addon-launch")]
fn test_build() -> Value {
    json!(LAUNCH_TEST_MARKER)
}
#[cfg(not(feature = "addon-launch"))]
fn test_build() -> Value {
    Value::Null
}

/// The single Premium seam for manager admission AND commit authorization.
/// Live since M8 (`addon_entitlement`).
pub(crate) fn premium() -> bool {
    // Live: today's date against the licence's expiry day, and activation
    // (`addon_entitlement`), the same decision every add-on write meets.
    crate::addon_entitlement::current() == crate::addon_entitlement::Access::Full
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    List,
    /// What opening the Add-ons panel does: the saved-data list, and (with
    /// Premium, when the throttle allows) the catalog, in ONE job so the two
    /// never race for the single job slot.
    Refresh,
    Inspect,
    Open,
    Install,
    Check,
    Update,
    Rollback,
    Remove,
    Export,
    Delete,
}
impl Action {
    fn paid(self) -> bool {
        match self {
            Self::Install => true,
            Self::Update => true,
            Self::Check | Self::Rollback => true,
            _ => false,
        }
    }
    fn ends_session(self) -> bool {
        matches!(
            self,
            Self::Install
                | Self::Update
                | Self::Rollback
                | Self::Remove
                | Self::Export
                | Self::Delete
        )
    }
    fn reason(self) -> Reason {
        match self {
            Self::Delete => Reason::DeleteData,
            Self::Remove => Reason::AddonRemove,
            Self::Export => Reason::WindowClose,
            _ => Reason::AddonUpdate,
        }
    }
}

pub(crate) fn gate(
    action: Action,
    unlocked: bool,
    entitled: bool,
    busy: bool,
) -> Result<(), &'static str> {
    if busy {
        return Err("busy");
    }
    // Removal of executable code is free even while the Vault is locked.
    if action != Action::Remove && !unlocked {
        return Err("not_unlocked");
    }
    if action.paid() && !entitled {
        return Err("premium_required");
    }
    Ok(())
}

fn open_mode(entitled: bool) -> addon_host::Mode {
    if entitled {
        addon_host::Mode::Full
    } else {
        addon_host::Mode::ReadOnly
    }
}

fn authorize(action: Action, entitled: bool) -> bool {
    !action.paid() || entitled
}
fn wait_for_quiescence(action: Action, quiet: bool) -> bool {
    action.ends_session() && !quiet
}

#[derive(Default)]
pub(crate) struct Manager {
    sequence: u64,
    job: Option<Job>,
    last: Option<Value>,
    /// What the panels show; replaced only by a worker's read (see `View`).
    view: View,
    /// Reads are numbered so an older one never replaces a newer one.
    view_reads: u64,
    view_applied: u64,
    /// Toolbar buttons the user hid (prefs `toolbar_hidden_addons`): `None`
    /// until the start-up read lands, then kept here and saved on change.
    hidden: Option<Vec<String>>,
    /// Add-ons the one-time banner has announced (prefs `announced_addons`):
    /// `None` until the start-up read lands, then kept here and saved on change.
    announced: Option<Vec<String>>,
    /// The earliest moment another catalog request may be made (P-4).
    catalog_next: Option<Instant>,
    catalog_fetched: bool,
    catalog_error: Option<&'static str>,
}
struct Job {
    sequence: u64,
    epoch: u64,
    id: String,
    action: Action,
    folder: Option<PathBuf>,
    cancel: Cancellation,
    started: bool,
    /// Refresh only: this job may ask for the catalog.
    fetch: bool,
    view_read: u64,
}

/// What the panels show, always read on a worker, never on the event loop:
/// the last accepted catalog (signature checked) and, per installed add-on,
/// its manifest's name and version and the rollback its saved index names.
#[derive(Default, Clone)]
pub(crate) struct View {
    catalog: Vec<patanyx_update::CatalogEntry>,
    /// When the held catalog stops being current (review R-003).
    catalog_expires: Option<u64>,
    installed: BTreeMap<String, InstalledSummary>,
}
pub(crate) struct ViewRead {
    read: u64,
    view: View,
    hidden: Vec<String>,
    announced: Vec<String>,
}

pub(crate) struct Completion {
    sequence: u64,
    result: Result<Output, &'static str>,
    view: Option<View>,
}
enum Output {
    Status(Value),
    Open(ServedBundle),
    Refreshed {
        ids: Vec<String>,
        /// Saved pages per named add-on, where they could be counted.
        pages: BTreeMap<String, usize>,
        fetch: Option<Result<(), (&'static str, Option<u64>)>>,
    },
}

fn read_view(store: Option<&InstallStore>) -> View {
    let Some(store) = store else {
        return View::default();
    };
    let saved = store.saved_catalog().ok().flatten();
    View {
        catalog_expires: saved.as_ref().map(|c| c.expires_at()),
        catalog: saved.map(|c| c.addons().to_vec()).unwrap_or_default(),
        installed: store
            .installed_ids()
            .into_iter()
            .filter_map(|id| Some((id.clone(), store.installed_summary(&id).ok()??)))
            .collect(),
    }
}

/// At start: what the panels show and which buttons are hidden, read once on a
/// worker.
pub(crate) fn load_view(app: &mut AppState) {
    app.addon_manager.view_reads += 1;
    let read = app.addon_manager.view_reads;
    let proxy = app.proxy();
    std::thread::spawn(move || {
        let view = read_view(InstallStore::production().ok().as_ref());
        let prefs = crate::prefs::load();
        let (hidden, announced) = (prefs.toolbar_hidden_addons, prefs.announced_addons);
        let _ = proxy.send_event(UserEvent::AddonViewRead(Box::new(ViewRead { read, view, hidden, announced })));
    });
}
pub(crate) fn view_read(app: &mut AppState, done: ViewRead) {
    let m = &mut app.addon_manager;
    if m.hidden.is_none() {
        m.hidden = Some(done.hidden);
    }
    if m.announced.is_none() {
        m.announced = Some(done.announced);
    }
    apply_view(m, done.read, done.view);
    publish(app);
}
fn apply_view(m: &mut Manager, read: u64, view: View) {
    if read > m.view_applied {
        m.view_applied = read;
        m.view = view;
    }
}
/// Whether any read of the saved catalog has landed. Until one has, an empty
/// `view.catalog` means "not read yet", not "none held", so the check owed at
/// unlock waits for it (addons.js, review R-036).
fn view_landed(m: &Manager) -> bool {
    m.view_applied > 0
}

/// Every add-on the panels can name: the catalog's entries and what is
/// installed. An add-on with no verified name gets no entry (its saved data
/// stays reachable in the Add-ons panel's data block).
fn known(view: &View) -> Vec<Value> {
    let mut ids: Vec<&str> = view.catalog.iter().map(|e| e.id()).collect();
    for id in view.installed.keys() {
        if !ids.contains(&id.as_str()) {
            ids.push(id);
        }
    }
    ids.into_iter()
        .filter_map(|id| {
            let entry = view.catalog.iter().find(|e| e.id() == id);
            let installed = view.installed.get(id);
            let name = entry.map(|e| e.name()).or(installed.map(|i| i.name.as_str()))?;
            let update = match (entry, installed) {
                (Some(e), Some(i)) => i.version.parse::<patanyx_update::Version>().is_ok_and(|v| e.version() > v),
                _ => false,
            };
            Some(json!({ "id": id, "name": name,
                "summary": entry.map(|e| e.summary()), "size": entry.map(|e| e.size()),
                "available": entry.map(|e| e.version().to_string()),
                "installed": installed.is_some(), "version": installed.map(|i| i.version.as_str()),
                "rollback": installed.and_then(|i| i.rollback.as_deref()), "update": update }))
        })
        .collect()
}

/// The one-time banner answered for one add-on: never announce it again.
pub(crate) fn set_announced(app: &mut AppState, id: &str) -> Result<Value, &'static str> {
    if !addon_host::id_ok(id) {
        return Err("invalid");
    }
    let mut prefs = crate::prefs::load();
    let mut announced = prefs.announced_addons.clone();
    announced.push(id.to_owned());
    prefs.announced_addons = crate::prefs::normalize_addon_ids(announced.iter().map(String::as_str));
    crate::prefs::save(&prefs).map_err(|_| "io")?;
    app.addon_manager.announced = Some(prefs.announced_addons);
    publish(app);
    Ok(status(app))
}

/// Show or hide one add-on's toolbar button (Customize). Its Tools menu entry
/// is not affected.
pub(crate) fn set_shown(app: &mut AppState, id: &str, shown: bool) -> Result<Value, &'static str> {
    if !addon_host::id_ok(id) {
        return Err("invalid");
    }
    let mut prefs = crate::prefs::load();
    let mut hidden = prefs.toolbar_hidden_addons.clone();
    hidden.retain(|h| h != id);
    if !shown {
        hidden.push(id.to_owned());
    }
    prefs.toolbar_hidden_addons = crate::prefs::normalize_addon_ids(hidden.iter().map(String::as_str));
    crate::prefs::save(&prefs).map_err(|_| "io")?;
    app.addon_manager.hidden = Some(prefs.toolbar_hidden_addons);
    publish(app);
    Ok(status(app))
}

/// A held catalog past its end date is shown as the old list (review R-003);
/// an unreadable clock counts as past it.
fn catalog_stale(expires: Option<u64>, now: Option<u64>) -> bool {
    expires.is_some_and(|expires| now.is_none_or(|now| now >= expires))
}

/// Whether opening the panel may become a catalog request now (P-4).
fn catalog_due(premium: bool, next: Option<Instant>, now: Instant) -> bool {
    premium && next.is_none_or(|next| now >= next)
}
/// How long after this answer before the next request may be made: the
/// success interval, or the failure interval or the server's Retry-After
/// (capped at an hour) when that is longer.
fn catalog_wait(fetch: &Result<(), (&'static str, Option<u64>)>) -> Duration {
    match fetch {
        Ok(()) => CATALOG_AFTER_SUCCESS,
        Err((_, retry_after)) => {
            CATALOG_AFTER_FAILURE.max(Duration::from_secs(retry_after.unwrap_or(0).min(3600)))
        }
    }
}

fn catalog_failure(error: &DeliveryError) -> (&'static str, Option<u64>) {
    match error {
        DeliveryError::Refused { code, retry_after } => (
            match code {
                Refusal::BadToken => "bad_token",
                Refusal::NotActivated => "not_activated",
                Refusal::Expired => "expired",
                Refusal::NotFound => "not_found",
                Refusal::RateLimited => "rate_limited",
                Refusal::Unavailable => "unavailable",
                _ => "delivery",
            },
            *retry_after,
        ),
        DeliveryError::Transport | DeliveryError::Redirect => ("network", None),
        DeliveryError::Cancelled => ("cancelled", None),
        // A genuine catalog past its end date is not a forged one: the service
        // has not published a current list (compliance advisory, 2026-10-21).
        DeliveryError::Install(InstallError::ExpiredCatalog) => ("catalog_expired", None),
        DeliveryError::Install(_) | DeliveryError::Response | DeliveryError::TooLarge => ("catalog_invalid", None),
        DeliveryError::Unavailable | DeliveryError::InvalidRequest => ("delivery", None),
    }
}

pub(crate) fn busy(app: &AppState) -> bool {
    app.addon_manager.job.is_some()
}
pub(crate) fn status(app: &AppState) -> Value {
    let m = &app.addon_manager;
    json!({ "visible": MANAGER_VISIBLE, "test_build": test_build(), "premium": premium(), "unlocked": app.vault.is_some(),
        "known": known(&m.view),
        "catalog": { "held": !m.view.catalog.is_empty(), "loaded": view_landed(m), "fetched": m.catalog_fetched, "error": m.catalog_error,
            "stale": catalog_stale(m.view.catalog_expires, addon_install::now().ok()) },
        "toolbar_hidden": m.hidden.clone().unwrap_or_default(),
        // The one-time banner: what it has announced, `null` until the start-up
        // read lands (so nothing is announced twice), and whether its tour page
        // may be opened at all (site_pages, PremiumTour).
        "announced": m.announced.clone(), "tour": crate::site_pages::SitePage::PremiumTour.available(),
        "pending": app.addon_manager.job.as_ref().map(|j| json!({ "action": j.action, "id": j.id,
            "phase": if j.started { "working" } else { "waiting" } })), "last": app.addon_manager.last,
        // A backup import holds the slot too, without a job of its own: the
        // check owed at unlock waits for it (addons.js, review R-042).
        "importing": crate::backup_job::importing(app) })
}
fn publish(app: &AppState) {
    app.emit("addon_manager", status(app));
}

/// Called before identity/network changes; no stale worker may activate code.
pub(crate) fn cancel(app: &AppState) {
    if let Some(job) = &app.addon_manager.job {
        job.cancel.cancel();
    }
}
pub(crate) fn before_command(app: &AppState, cmd: &str) {
    if matches!(
        cmd,
        "licence_paste"
            | "licence_remove"
            | "licence_release"
            | "licence_import_receipt"
            | "tunnel_import"
            | "tunnel_import_text"
            | "tunnel_apply_restart"
            | "tunnel_set_mode"
            | "tunnel_remove"
    ) {
        cancel(app);
    }
}

pub(crate) fn start(
    app: &mut AppState,
    action: Action,
    id: &str,
    confirmed: bool,
) -> Result<Value, &'static str> {
    let result = start_inner(app, action, id, confirmed);
    if let Err(error) = result {
        app.addon_manager.last = Some(json!({ "id": id, "action": action, "error": error }));
        publish(app);
    }
    result
}

fn start_inner(
    app: &mut AppState,
    action: Action,
    id: &str,
    confirmed: bool,
) -> Result<Value, &'static str> {
    gate(
        action,
        app.vault.is_some(),
        premium(),
        busy(app) || crate::backup_job::importing(app),
    )?;
    if !matches!(action, Action::List | Action::Refresh) && !addon_host::id_ok(id) {
        return Err("invalid");
    }
    if matches!(action, Action::Export | Action::Delete | Action::Remove) && !confirmed {
        return Err("confirmation_required");
    }
    let folder = if action == Action::Export {
        let title = app.i18n.text("addon-export-folder");
        let choose = app.i18n.text("addon-choose");
        let cancel = app.i18n.text("addon-cancel");
        let Some(folder) =
            crate::platform::pick_addon_export_folder(&app.hosts, &title, &choose, &cancel)
        else {
            return Ok(json!({ "cancelled": true }));
        };
        // Native chooser runs a nested loop. Recheck after it returns.
        gate(
            action,
            app.vault.is_some(),
            premium(),
            busy(app) || crate::backup_job::importing(app),
        )?;
        Some(folder)
    } else {
        None
    };
    // The throttle is decided here, on the loop, and the next allowed moment
    // is pushed out BEFORE the request, so a job that never completes still
    // counts as an attempt (P-4).
    let now = Instant::now();
    let fetch = action == Action::Refresh && catalog_due(premium(), app.addon_manager.catalog_next, now);
    if fetch {
        app.addon_manager.catalog_next = Some(now + CATALOG_AFTER_FAILURE);
    }
    app.addon_manager.view_reads += 1;
    let view_read = app.addon_manager.view_reads;
    app.addon_manager.sequence += 1;
    app.addon_manager.job = Some(Job {
        sequence: app.addon_manager.sequence,
        epoch: app.vault_epoch,
        id: id.into(),
        action,
        folder,
        cancel: Cancellation::new(),
        started: false,
        fetch,
        view_read,
    });
    if action.ends_session() {
        addon_session::end(app, action.reason(), Then::NOTHING);
    }
    resume(app);
    Ok(status(app))
}

/// Called after teardown frames, deadlines and AddonWorkerQuiet. No polling,
/// sleeps or waits on the event loop.
pub(crate) fn resume(app: &mut AppState) {
    let Some(job) = &app.addon_manager.job else {
        return;
    };
    if job.started {
        return;
    }
    let action = job.action;
    if wait_for_quiescence(action, addon_session::quiescent(app)) {
        publish(app);
        return;
    }
    let valid = gate(
        action,
        app.vault.is_some(),
        premium(),
        crate::backup_job::importing(app),
    )
    .and_then(|_| {
        app.addon_manager
            .job
            .as_ref()
            .unwrap()
            .cancel
            .check()
            .map_err(|_| "cancelled")
    });
    if let Err(code) = valid {
        fail(app, code);
        return;
    }
    let job = app.addon_manager.job.as_mut().unwrap();
    let input = if matches!(action, Action::Export | Action::Delete) {
        match app
            .store
            .as_ref()
            .ok_or("not_unlocked")
            .and_then(|s| s.addon_namespace_input(&job.id).map_err(|_| "io"))
        {
            Ok(input) => Some(input),
            Err(code) => {
                fail(app, code);
                return;
            }
        }
    } else {
        None
    };
    // Refresh counts each named add-on's saved pages for its panel: keys taken
    // here from the unlocked Library, namespaces opened on the worker, and
    // only those that already exist on disk (opening never creates one).
    let page_inputs: Vec<(String, patanyx_store::AddonNamespaceInput)> = if action == Action::Refresh {
        let view = &app.addon_manager.view;
        let mut ids: Vec<&str> = view.catalog.iter().map(|e| e.id()).collect();
        ids.extend(view.installed.keys().map(String::as_str));
        ids.sort_unstable();
        ids.dedup();
        ids.into_iter()
            .filter_map(|id| Some((id.to_owned(), app.store.as_ref()?.addon_namespace_input(id).ok()?)))
            .collect()
    } else {
        Vec::new()
    };
    let fetch = job.fetch;
    let mut token = if action.paid() || fetch {
        app.vault
            .as_ref()
            .and_then(|v| v.licence_record())
            .map(|mut r| {
                let token = zeroize::Zeroizing::new(std::mem::take(&mut r.token_text));
                r.token_text.zeroize();
                token
            })
    } else {
        None
    };
    job.started = true;
    let (sequence, id, folder, cancel) = (
        job.sequence,
        job.id.clone(),
        job.folder.take(),
        job.cancel.clone(),
    );
    let vault_path = app.vault_path.clone();
    let store_path = app.store_path.clone();
    let proxy = app.proxy();
    // A Library replacement cannot race a worker holding the old namespace.
    let quiet = Arc::new(());
    app.addon_draining.push(quiet.clone());
    std::thread::spawn(move || {
        // Credentials for the licence service, built once from the token the
        // Vault gave this job and this device's id.
        let client = |token: &mut Option<zeroize::Zeroizing<String>>| -> Result<DeliveryClient, &'static str> {
            let device = crate::activation::device_id_if_present(&vault_path)
                .map_err(|_| "credentials")?
                .ok_or("credentials")?;
            let auth = Credentials::new(
                token.take().ok_or("credentials")?.to_string(),
                crate::activation::hex_encode_16(&device),
            )
            .map_err(|_| "credentials")?;
            Ok(DeliveryClient::new(auth, cancel.clone()))
        };
        let result = (|| {
            cancel.check().map_err(|_| "cancelled")?;
            if action == Action::List {
                return addon_data::namespaces(&store_path)
                    .map(|ids| Output::Status(json!({ "ids": ids })));
            }
            if action == Action::Refresh {
                let ids = addon_data::namespaces(&store_path)?;
                let pages = page_inputs
                    .into_iter()
                    .filter(|(id, _)| ids.contains(id))
                    .filter_map(|(id, input)| {
                        let listed = input.open().ok()?.backup_pages().ok()?;
                        Some((id, listed.map_or(0, |list| list.len())))
                    })
                    .collect();
                let fetch = fetch.then(|| {
                    let store = InstallStore::production().map_err(|_| ("delivery", None))?;
                    let client = client(&mut token).map_err(|code| (code, None))?;
                    client.catalog(&store).map(|_| ()).map_err(|e| catalog_failure(&e))
                });
                return Ok(Output::Refreshed { ids, pages, fetch });
            }
            if let Some(input) = input {
                let namespace = input.open().map_err(|_| "io")?;
                return match action {
                    Action::Export => {
                        addon_data::export(&namespace, folder.as_deref().ok_or("folder")?, &cancel)
                            .map(|report| Output::Status(json!({ "export": report })))
                    }
                    Action::Delete => addon_data::delete(
                        namespace,
                        &crate::platform::addon_profile_dir_for(&vault_path, &id),
                        &cancel,
                    )
                    .map(|_| Output::Status(json!({ "deleted": true }))),
                    _ => unreachable!(),
                };
            }
            if matches!(action, Action::Open | Action::Inspect) {
                return match addon_install::installed_bundle(&id) {
                    Ok(bundle) => {
                        if action == Action::Inspect {
                            return Ok(Output::Status(metadata(&bundle)));
                        }
                        Ok(Output::Open(served(bundle)))
                    }
                    Err(InstallError::NotInstalled) if action == Action::Inspect => {
                        Ok(Output::Status(json!({ "installed": false })))
                    }
                    Err(e) => Err(install_code(e)),
                };
            }
            let store = InstallStore::production().map_err(install_code)?;
            // Captured cancellation binds this worker to the same licence,
            // Vault and network policy. Premium is checked again at commit.
            let authorize = || authorize(action, premium());
            match action {
                Action::Remove => store
                    .uninstall(&id, &cancel, authorize)
                    .map_err(install_code)?,
                // Offline from the release already on disk; when the saved
                // index that authorizes it has expired, renew it first (P-5).
                Action::Rollback => match store.rollback(&id, &cancel, authorize) {
                    Err(InstallError::ExpiredIndex) => {
                        client(&mut token)?.check(&id, &store).map_err(|_| "delivery")?;
                        store.rollback(&id, &cancel, authorize).map_err(install_code)?
                    }
                    other => other.map_err(install_code)?,
                },
                Action::Install | Action::Check | Action::Update => {
                    if !premium() {
                        return Err("premium_required");
                    }
                    let client = client(&mut token)?;
                    if action == Action::Check {
                        let index = client.check(&id, &store).map_err(|_| "delivery")?;
                        return Ok(Output::Status(
                            json!({ "available": index.current().version().to_string(),
                            "rollback": index.rollback().map(|r| r.version().to_string()) }),
                        ));
                    }
                    let prepared = client
                        .download(&id, ReleaseChoice::Current, &store)
                        .map_err(|_| "delivery")?;
                    store
                        .activate(prepared, &cancel, authorize)
                        .map_err(install_code)?;
                }
                _ => unreachable!(),
            }
            if action == Action::Remove {
                Ok(Output::Status(json!({ "installed": false })))
            } else {
                Ok(Output::Status(metadata(
                    &addon_install::installed_bundle(&id).map_err(install_code)?,
                )))
            }
        })();
        drop(token);
        // What the panels show after this job, read here, off the loop. The
        // saved-data jobs change nothing the panels read.
        let view = (!matches!(action, Action::List | Action::Export | Action::Delete))
            .then(|| read_view(InstallStore::production().ok().as_ref()));
        drop(quiet);
        let _ = proxy.send_event(UserEvent::AddonManagerDone(Box::new(Completion {
            sequence,
            result,
            view,
        })));
        let _ = proxy.send_event(UserEvent::AddonWorkerQuiet);
    });
    publish(app);
}
fn fail(app: &mut AppState, code: &'static str) {
    if let Some(job) = app.addon_manager.job.take() {
        app.addon_manager.last = Some(json!({ "id": job.id, "action": job.action, "error": code }));
    }
    publish(app);
}
pub(crate) fn complete(app: &mut AppState, done: Completion) {
    let Some(job) = &app.addon_manager.job else {
        return;
    };
    if job.sequence != done.sequence {
        return;
    }
    // The licence service answered: that sets the next allowed request even
    // if the job is then cancelled (the Vault locked meanwhile), so a lock
    // never shortens the wait (review R-002).
    if let Ok(Output::Refreshed { fetch: Some(fetch), .. }) = &done.result {
        let m = &mut app.addon_manager;
        m.catalog_next = Some(Instant::now() + catalog_wait(fetch));
        match fetch {
            Ok(()) => {
                m.catalog_fetched = true;
                m.catalog_error = None;
            }
            Err((code, _)) => m.catalog_error = Some(code),
        }
    }
    let Some(job) = &app.addon_manager.job else {
        return;
    };
    if job.cancel.check().is_err()
        || (job.action != Action::Remove && (job.epoch != app.vault_epoch || app.vault.is_none()))
    {
        fail(app, "cancelled");
        return;
    }
    let job = app.addon_manager.job.take().unwrap();
    if let Some(view) = done.view {
        apply_view(&mut app.addon_manager, job.view_read, view);
    }
    let result = done.result.and_then(|out| match out {
        Output::Status(value) => Ok(value),
        Output::Refreshed { ids, pages, .. } => Ok(json!({ "ids": ids, "pages": pages })),
        Output::Open(bundle) => {
            let data = json!({ "installed": true, "name": bundle.name, "version": bundle.version });
            addon_host::open(app, bundle).map_err(|e| {
                if e == "busy" || e == "already_open" {
                    "busy"
                } else {
                    "open_failed"
                }
            })?;
            if let Some(session) = &app.addon {
                session.mode.set(open_mode(premium()));
            }
            app.reveal_addon();
            Ok(data)
        }
    });
    app.addon_manager.last = Some(match result {
        Ok(data) => json!({ "id": job.id, "action": job.action, "data": data }),
        Err(error) => json!({ "id": job.id, "action": job.action, "error": error }),
    });
    publish(app);
}
fn metadata(bundle: &addon_install::VerifiedBundle) -> Value {
    json!({ "installed": true, "name": bundle.manifest().name(), "version": bundle.manifest().version().to_string() })
}
fn served(bundle: addon_install::VerifiedBundle) -> ServedBundle {
    ServedBundle {
        id: bundle.manifest().id().into(),
        name: bundle.manifest().name().into(),
        version: bundle.manifest().version().to_string(),
        files: bundle
            .files()
            .iter()
            .map(|(path, bytes)| (path.clone(), Arc::new(bytes.clone())))
            .collect(),
    }
}
fn install_code(error: InstallError) -> &'static str {
    match error {
        InstallError::Unconfigured => "unconfigured",
        InstallError::Busy => "busy",
        InstallError::Cancelled => "cancelled",
        InstallError::NotInstalled => "not_installed",
        InstallError::Unauthorized => "unauthorized",
        _ => "install_failed",
    }
}

#[cfg(test)]
#[path = "addon_manager_tests.rs"]
mod tests;
