mod basemap;

use tauri_plugin_sql::{Migration, MigrationKind};

/// Show a fatal startup error to the operator.
///
/// The binary is built with `windows_subsystem = "windows"`, so it has no
/// console: the `.expect()` this replaces produced a panic with nowhere to
/// print, and the process just disappeared. "I double-clicked the icon and
/// nothing happened", with no log and nothing to report.
///
/// The failure this is most likely to carry is a migration checksum mismatch.
/// sqlx hashes each migration over the **entire file text, comments included**,
/// and compares it on every start, so editing so much as a typo in a comment in
/// any of the fourteen migration files — six of which are 70-85% prose — makes
/// every existing installation refuse to open. Naming the version in the
/// message is the difference between a five-minute fix and an unexplained
/// brick.
#[cfg(windows)]
fn show_fatal_error(message: &str) {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    let body = HSTRING::from(message);
    let title = HSTRING::from("LOCKON EWAC could not start");
    unsafe {
        MessageBoxW(None, &body, &title, MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn show_fatal_error(message: &str) {
    eprintln!("LOCKON EWAC could not start: {message}");
}

/// Put this process in a job object so every descendant dies with it.
///
/// `tauri-plugin-shell` kills the children it tracks on `RunEvent::Exit`, and
/// the engine also exits on stdin EOF, so a clean window close already reaps
/// the sidecar. Neither covers the cases that matter:
///
///   * A hard kill — Task Manager's "End task", or a panic that aborts — never
///     reaches `RunEvent::Exit`.
///   * The engine's own children are not tracked by anything. The interpreter
///     exits without unwinding its daemon threads, so a `hashcat` it launched
///     can outlive the application indefinitely.
///
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` makes the kernel terminate every
/// process in the job once the last handle to it closes, which happens when
/// this process dies for any reason. Assigning *this* process rather than the
/// sidecar is deliberate: descendants inherit the job, so it covers the engine
/// and anything the engine starts, without needing a pid the Rust side never
/// sees (the sidecar is spawned from the frontend).
///
/// The handle is leaked on purpose. Closing it would trigger the kill.
///
/// Failure is not fatal. Nested jobs are supported from Windows 8, but a
/// launcher that already placed us in a job with incompatible limits can refuse
/// this, and that is a reason to run without the safety net rather than not to
/// run.
#[cfg(windows)]
fn confine_descendants_to_job() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        // An unnamed job: nothing else needs to find it, and a name would let
        // another process open and interfere with it.
        let job: HANDLE = match CreateJobObjectW(None, windows::core::PCWSTR::null()) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[lifecycle] could not create job object: {e}");
                return;
            }
        };

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) {
            eprintln!("[lifecycle] could not set job limits: {e}");
            return;
        }

        if let Err(e) = AssignProcessToJobObject(job, GetCurrentProcess()) {
            eprintln!("[lifecycle] could not assign process to job: {e}");
            return;
        }

        // The handle is intentionally left open for the process lifetime.
        //
        // `HANDLE` is a plain copyable value with no `Drop`, so there is nothing
        // to leak and nothing to suppress — it simply is never closed, because
        // `CloseHandle` is never called on it. That is the point:
        // KILL_ON_JOB_CLOSE fires when the last handle to the job goes away, so
        // closing this early would terminate the very processes it is meant to
        // outlive. It is released by the kernel when this process exits, which
        // is exactly when the kill should happen.
    }
}

#[cfg(not(windows))]
fn confine_descendants_to_job() {}

// `get_wifi_ssid` was removed.
//
// It shelled out to `netsh wlan show interfaces` and had three faults, all of
// which `engine/scanner/net_context.py` had already solved for the same output:
//
//   * No CREATE_NO_WINDOW. This is a GUI-subsystem binary with no console, so
//     Windows allocated one per child — a black window blinked on screen every
//     five seconds for as long as the Intrusion page was open, because the
//     frontend polled it on a timer.
//   * It matched the literal English field name `SSID`, so on a localised
//     Windows it reported "Disconnected" forever while the adapter was
//     associated.
//   * It was an `async fn` performing a blocking `Command::output()`, parking a
//     Tauri runtime worker for the 100-800 ms netsh takes — a thread that also
//     serves every other IPC call.
//
// The engine already publishes the associated SSID in `net_context`, and the
// frontend already keeps that in `engineStore`. Two implementations of one
// lookup, where the worse one was the one being used.

use serde::Serialize;
use std::sync::Mutex;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

struct SystemState(Mutex<System>);

#[derive(Serialize)]
struct SystemVitals {
    cpu_usage: f32,
    ram_usage: f32,
    ram_total: f32,
}

// `async`, so this does not run on the thread handling the IPC message.
//
// A non-`async` `#[tauri::command]` compiles to `ExecutionContext::Blocking` and is
// resolved inline on the main thread. `TopBar` polls this on a two-second interval for
// the entire life of the application, so `refresh_cpu_usage()` and `refresh_memory()`
// were running on the UI thread under a mutex, forever. Each call is only single-digit
// milliseconds on Windows, but it is permanent, and it is the same mistake the comment
// above `get_wifi_ssid`'s removal describes. The `async` marker routes it to the sync
// threadpool instead; the body does not need to change.
#[tauri::command(async)]
fn get_system_vitals(state: tauri::State<'_, SystemState>) -> Result<SystemVitals, String> {
    // `lock().unwrap()` panicked on a poisoned mutex, and a `std::sync::Mutex`
    // stays poisoned forever once any thread panics while holding it — so one
    // panic anywhere in this critical section would make every subsequent
    // vitals poll panic too. The command already returns a Result; an error is
    // the correct way to say "not available", and the TopBar renders that as a
    // missing reading rather than taking the app down.
    let mut sys = state
        .0
        .lock()
        .map_err(|e| format!("system state unavailable: {e}"))?;
    // Refreshing CPU usage requires it to be called twice with some delay if new, 
    // but since we keep the state, it will be accurate on subsequent polls.
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let cpus = sys.cpus();
    let cpu_usage = if !cpus.is_empty() {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    } else {
        0.0
    };

    let ram_usage = sys.used_memory() as f32 / 1024.0 / 1024.0 / 1024.0;
    let ram_total = sys.total_memory() as f32 / 1024.0 / 1024.0 / 1024.0;

    Ok(SystemVitals {
        cpu_usage,
        ram_usage,
        ram_total,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let migrations = vec![
        Migration {
            version: 1,
            description: "create_initial_schema",
            sql: include_str!("../migrations/001_initial_schema.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 2,
            description: "create_intrusion_schema",
            sql: include_str!("../migrations/002_intrusion_schema.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 3,
            description: "create_wardriving_schema",
            sql: include_str!("../migrations/003_wardriving_schema.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 4,
            description: "create_benchmark_schema",
            sql: include_str!("../migrations/004_benchmark_schema.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 5,
            description: "create_credential_vault",
            sql: include_str!("../migrations/005_credential_vault.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 6,
            description: "create_reports_schema",
            sql: include_str!("../migrations/006_reports_schema.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 7,
            description: "create_cracking_history",
            sql: include_str!("../migrations/007_cracking_history.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 8,
            description: "create_integrity_and_scope",
            sql: include_str!("../migrations/008_integrity_and_scope.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 9,
            description: "create_findings_and_evidence",
            sql: include_str!("../migrations/009_findings_and_evidence.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 10,
            description: "add_rogue_ap_verdict",
            sql: include_str!("../migrations/010_rogue_ap_verdict.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 11,
            description: "add_location_uncertainty",
            sql: include_str!("../migrations/011_location_uncertainty.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 12,
            description: "encrypt_credential_vault",
            sql: include_str!("../migrations/012_credential_vault_encryption.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 13,
            description: "wps_measurement",
            sql: include_str!("../migrations/013_wps_measurement.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 14,
            description: "vault_page_reclaim",
            sql: include_str!("../migrations/014_vault_page_reclaim.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 15,
            description: "live_ap_fields",
            sql: include_str!("../migrations/015_live_ap_fields.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 16,
            description: "query_indexes",
            sql: include_str!("../migrations/016_query_indexes.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 17,
            description: "cracking_history_vault",
            sql: include_str!("../migrations/017_cracking_history_vault.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 18,
            description: "missing_query_indexes",
            sql: include_str!("../migrations/018_missing_query_indexes.sql"),
            kind: MigrationKind::Up,
        },
        Migration {
            version: 19,
            description: "one_active_engagement",
            sql: include_str!("../migrations/019_one_active_engagement.sql"),
            kind: MigrationKind::Up,
        },
    ];

    // Before anything is spawned, so the engine and whatever it starts are
    // inside the job from the moment they exist.
    confine_descendants_to_job();

    // Only what `get_system_vitals` reads.
    //
    // `System::new_all()` enumerates every process, disk, network interface and
    // component before the window opens, and keeps the resulting process table alive in
    // `SystemState` for the life of the application -- while the only things ever read
    // from it are `cpus()`, `used_memory()` and `total_memory()`. On a cold start that
    // is work the operator waits for and memory nobody uses.
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
            .with_memory(MemoryRefreshKind::nothing().with_ram()),
    );
    // CPU usage needs two samples to mean anything; this is the first.
    sys.refresh_cpu_usage();

    // `build()` rather than `run()`, so a setup failure is catchable.
    //
    // This was `.run(...).expect("error while running LOCKON EWAC")`. The
    // plugin's migration work happens during build, and any failure there —
    // most plausibly a migration checksum mismatch after an edit, or two
    // instances racing the migrations on a fresh profile — propagated into the
    // `expect()` and panicked a binary with no console attached. Nothing was
    // printed, no dialog appeared, and the process vanished.
    let app = match tauri::Builder::default()
        /*
          One instance per machine, and this has to be the first plugin.

          Two copies of LOCKON open one SQLite file through two sqlx pools and
          two sidecars. Three consequences, in order of how badly they end:

            * Both run the migrations on a fresh profile. sqlx takes no lock
              across processes, so they race `_sqlx_migrations` and one of them
              loses with a checksum or "already applied" error — the failure the
              dialog below exists to explain, arrived at without anyone editing
              a migration.
            * Two engines, two radios' worth of commands to one adapter. A
              deauthentication started in one window cannot be stopped from the
              other, because the strike state lives in the engine that sent it.
            * Both write to `access_points` and `scan_logs` for the same
              mission. The rows interleave, and a report built afterwards
              cannot tell which sighting came from which drive.

          The second instance focuses the existing window instead of exiting
          silently: an operator who double-clicks the icon wants the app, and a
          launcher that appears to do nothing is the reason they click again.
        */
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(SystemState(Mutex::new(sys)))
        .invoke_handler(tauri::generate_handler![
            get_system_vitals,
            basemap::basemap_status,
            basemap::read_basemap_range
        ])
        .plugin(
            tauri_plugin_sql::Builder::default()
                .add_migrations("sqlite:ewac.db", migrations)
                .build(),
        )
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        // `tauri_plugin_opener` was registered here and used nowhere. Its default
        // permission set grants `allow-open-url`, so script in the webview could
        // launch the default browser at any http(s) URL -- an exfiltration channel the
        // CSP cannot see, because `connect-src` does not govern handing a URL to the
        // shell. This renderer also holds `sql:allow-execute`, so it can read the whole
        // survey database, the audit trail and the vault rows; and it displays SSIDs,
        // hostnames and service banners chosen by whoever owns the equipment being
        // assessed, which is why the CSP exists at all. A capability nothing uses is
        // not worth that.
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(e) => {
            let detail = e.to_string();
            // A checksum mismatch is the failure an operator has no chance of
            // diagnosing on their own, so it is named explicitly and the fix is
            // spelled out.
            let hint = if detail.contains("checksum")
                || detail.contains("VersionMismatch")
                || detail.contains("was previously applied")
            {
                "\n\nThis looks like a database migration mismatch: a migration file in this \
                 build differs from the one that was applied to your existing database. sqlx \
                 hashes the whole file, comments included, so even a reworded comment causes \
                 this.\n\nEither install the build this database was created with, or move \
                 the existing ewac.db aside to start a fresh one (you will lose archived \
                 surveys, so copy it somewhere first)."
            } else if detail.contains("already exists") {
                "\n\nThis can happen when two copies of LOCKON EWAC start at the same time and \
                 both try to create the database. Close all copies and open one."
            } else {
                ""
            };
            show_fatal_error(&format!("{detail}{hint}"));
            std::process::exit(1);
        }
    };

    app.run(|_app, _event| {});
}
