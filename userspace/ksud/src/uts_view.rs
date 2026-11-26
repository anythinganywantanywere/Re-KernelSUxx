//! Minimal UTS View userspace driver.
//!
//! Pushes a UTS (uname) spoofing template to the kernel-side UTS View
//! feature through the `KSU_IOCTL_GET/SET_UTS_VIEW_CONFIG` supercalls and
//! toggles it through the `uts_view` feature id. This module never installs
//! anything and never patches the kernel: it only talks to a kernel that
//! already carries the feature (the wire layout is `ksu_uts_view_config`
//! in `uapi/uts_view.h`; the ABI is 972 bytes, checked by a host test).
//!
//! Two modes, mirroring the kernel:
//! - GLOBAL (default): the spoofed values are written into `init_uts_ns`,
//!   so `os.version`, the `uname()` syscall and `uname -r` all report the
//!   same values, exactly like the SUSFS SPOOF_UNAME this replaces.
//!   Spoofing only the syscall would leave `os.version` untouched and the
//!   mismatch itself would be a detection signal.
//! - SELECTED: only UIDs in the target list get a private UTS namespace
//!   with the spoofed values, applied when a zygote-spawned app takes its
//!   app UID. The kernel composes with a prior SUSFS spoof by
//!   last-writer-wins on `init_uts_ns`: disabling UTS View restores the
//!   values that were there before it was enabled.
//!
//! Every setter applies live and records the value in `uts_view.json`
//! under the ksud working directory, so `uts apply` (run at boot) can
//! re-apply the same configuration after a reboot. The stored config is a
//! plain JSON object.

use std::os::raw::c_char;

use anyhow::{Result, bail};
use serde_json::{Value, json};

#[cfg(target_os = "android")]
use anyhow::Context;
#[cfg(target_os = "android")]
use const_format::concatcp;
#[cfg(target_os = "android")]
use std::path::Path;

#[cfg(target_os = "android")]
use clap::Subcommand;
#[cfg(target_os = "android")]
use log::{info, warn};

#[cfg(target_os = "android")]
use crate::ksu_uapi;
#[cfg(target_os = "android")]
use crate::ksucalls;

#[cfg(target_os = "android")]
const CONFIG_PATH: &str = concatcp!(crate::defs::WORKING_DIR, "uts_view.json");

/// `__NEW_UTS_LEN + 1`: 64 usable characters plus the NUL terminator.
const UTS_NAME_LEN: usize = 65;
/// Maximum targets the kernel accepts (`KSU_UTS_MAX_TARGETS`).
const MAX_TARGETS: usize = 128;
/// Smallest UID a target may have (`is_appuid`).
const MIN_TARGET_UID: u32 = 10000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UtsMode {
    #[default]
    Global,
    Selected,
}

impl UtsMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Selected => "selected",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "global" => Ok(Self::Global),
            "selected" => Ok(Self::Selected),
            other => bail!("unknown uts mode '{other}' (expected global|selected)"),
        }
    }

    /// Android-only: the mode constants come from the bindgen UAPI, which
    /// is only generated for the Android target.
    #[cfg(target_os = "android")]
    const fn to_wire(self) -> u32 {
        match self {
            Self::Global => ksu_uapi::KSU_UTS_MODE_GLOBAL,
            Self::Selected => ksu_uapi::KSU_UTS_MODE_SELECTED,
        }
    }

    #[cfg(target_os = "android")]
    const fn from_wire(mode: u32) -> Self {
        if mode & ksu_uapi::KSU_UTS_MODE_SELECTED != 0 {
            Self::Selected
        } else {
            Self::Global
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub mode: UtsMode,
    pub sysname: Option<String>,
    pub nodename: Option<String>,
    pub release: Option<String>,
    pub version: Option<String>,
    pub machine: Option<String>,
    pub domainname: Option<String>,
    pub targets: Vec<u32>,
    pub enabled: bool,
}

fn config_to_json(config: &Config) -> Value {
    let mut value = json!({
        "version": 1,
        "mode": config.mode.as_str(),
        "targets": config.targets,
        "enabled": config.enabled,
    });
    if let Some(sysname) = &config.sysname {
        value["sysname"] = json!(sysname);
    }
    if let Some(nodename) = &config.nodename {
        value["nodename"] = json!(nodename);
    }
    if let Some(release) = &config.release {
        value["release"] = json!(release);
    }
    if let Some(version) = &config.version {
        value["version"] = json!(version);
    }
    if let Some(machine) = &config.machine {
        value["machine"] = json!(machine);
    }
    if let Some(domainname) = &config.domainname {
        value["domainname"] = json!(domainname);
    }
    value
}

fn config_from_json(value: &Value) -> Config {
    let mut config = Config::default();
    if let Some(mode) = value.get("mode").and_then(Value::as_str) {
        config.mode = UtsMode::parse(mode).unwrap_or_default();
    }
    if let Some(sysname) = value.get("sysname").and_then(Value::as_str) {
        config.sysname = Some(sysname.to_owned());
    }
    if let Some(nodename) = value.get("nodename").and_then(Value::as_str) {
        config.nodename = Some(nodename.to_owned());
    }
    if let Some(release) = value.get("release").and_then(Value::as_str) {
        config.release = Some(release.to_owned());
    }
    if let Some(version) = value.get("version").and_then(Value::as_str) {
        config.version = Some(version.to_owned());
    }
    if let Some(machine) = value.get("machine").and_then(Value::as_str) {
        config.machine = Some(machine.to_owned());
    }
    if let Some(domainname) = value.get("domainname").and_then(Value::as_str) {
        config.domainname = Some(domainname.to_owned());
    }
    if let Some(targets) = value.get("targets").and_then(Value::as_array) {
        config.targets = targets
            .iter()
            .filter_map(Value::as_u64)
            .map(|uid| uid as u32)
            .collect();
    }
    config.enabled = value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    config
}

/// Validate one UTS name field: at most 64 characters, no embedded NUL.
/// Mirrors `validate_config` in `kernel/feature/uts_view.c`.
fn field_bytes(value: &str) -> Result<[c_char; UTS_NAME_LEN]> {
    if value.len() > UTS_NAME_LEN - 1 {
        bail!("uts field exceeds 64 characters: '{value}'");
    }
    if value.contains('\0') {
        bail!("uts field contains a NUL byte");
    }
    let mut buf = [0 as c_char; UTS_NAME_LEN];
    for (i, byte) in value.bytes().enumerate() {
        // `c_char` is u8 on Android and i8 on the host; `as _` keeps this
        // compiling (and clippy-clean) on both.
        buf[i] = byte as _;
    }
    Ok(buf)
}

/// Read one UTS name field back out of a wire struct. Android-only: the
/// only caller is `config_from_wire`.
#[cfg(target_os = "android")]
fn field_string(buf: &[c_char; UTS_NAME_LEN]) -> Option<String> {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as _)
        .collect();
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Validate the SELECTED target list: app UIDs only, no duplicates, at
/// most `KSU_UTS_MAX_TARGETS`. Mirrors `validate_config` in the kernel.
fn validate_targets(targets: &[u32]) -> Result<()> {
    if targets.len() > MAX_TARGETS {
        bail!("too many uts targets (max {MAX_TARGETS})");
    }
    let mut sorted = targets.to_vec();
    sorted.sort_unstable();
    for (i, &uid) in sorted.iter().enumerate() {
        if uid < MIN_TARGET_UID {
            bail!("uts target {uid} is not an app uid (>= {MIN_TARGET_UID})");
        }
        if i > 0 && sorted[i - 1] == uid {
            bail!("duplicate uts target {uid}");
        }
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn config_to_wire(config: &Config) -> Result<ksu_uapi::ksu_uts_view_config> {
    validate_targets(&config.targets)?;
    let mut wire: ksu_uapi::ksu_uts_view_config = unsafe { std::mem::zeroed() };
    wire.mode = config.mode.to_wire();
    let mut mask = 0u32;
    if let Some(sysname) = &config.sysname {
        wire.sysname = field_bytes(sysname)?;
        mask |= ksu_uapi::KSU_UTS_FIELD_SYSNAME;
    }
    if let Some(nodename) = &config.nodename {
        wire.nodename = field_bytes(nodename)?;
        mask |= ksu_uapi::KSU_UTS_FIELD_NODENAME;
    }
    if let Some(release) = &config.release {
        wire.release = field_bytes(release)?;
        mask |= ksu_uapi::KSU_UTS_FIELD_RELEASE;
    }
    if let Some(version) = &config.version {
        wire.version = field_bytes(version)?;
        mask |= ksu_uapi::KSU_UTS_FIELD_VERSION;
    }
    if let Some(machine) = &config.machine {
        wire.machine = field_bytes(machine)?;
        mask |= ksu_uapi::KSU_UTS_FIELD_MACHINE;
    }
    if let Some(domainname) = &config.domainname {
        wire.domainname = field_bytes(domainname)?;
        mask |= ksu_uapi::KSU_UTS_FIELD_DOMAINNAME;
    }
    wire.field_mask = mask;
    wire.target_count = config.targets.len() as u32;
    for (i, &uid) in config.targets.iter().enumerate() {
        wire.target_uids[i] = uid;
    }
    Ok(wire)
}

#[cfg(target_os = "android")]
fn config_from_wire(wire: &ksu_uapi::ksu_uts_view_config) -> Config {
    let mut config = Config {
        mode: UtsMode::from_wire(wire.mode),
        ..Default::default()
    };
    if wire.field_mask & ksu_uapi::KSU_UTS_FIELD_SYSNAME != 0 {
        config.sysname = field_string(&wire.sysname);
    }
    if wire.field_mask & ksu_uapi::KSU_UTS_FIELD_NODENAME != 0 {
        config.nodename = field_string(&wire.nodename);
    }
    if wire.field_mask & ksu_uapi::KSU_UTS_FIELD_RELEASE != 0 {
        config.release = field_string(&wire.release);
    }
    if wire.field_mask & ksu_uapi::KSU_UTS_FIELD_VERSION != 0 {
        config.version = field_string(&wire.version);
    }
    if wire.field_mask & ksu_uapi::KSU_UTS_FIELD_MACHINE != 0 {
        config.machine = field_string(&wire.machine);
    }
    if wire.field_mask & ksu_uapi::KSU_UTS_FIELD_DOMAINNAME != 0 {
        config.domainname = field_string(&wire.domainname);
    }
    let count = wire.target_count as usize;
    config.targets = wire.target_uids[..count.min(MAX_TARGETS)].to_vec();
    config
}

#[cfg(target_os = "android")]
pub fn load_config() -> Result<Config> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("Read {CONFIG_PATH}"))?;
    let value: Value = serde_json::from_str(&text).context("Parse uts_view config")?;
    Ok(config_from_json(&value))
}

#[cfg(target_os = "android")]
pub fn save_config(config: &Config) -> Result<()> {
    let dir = Path::new(crate::defs::WORKING_DIR);
    std::fs::create_dir_all(dir).context("Create ksud working directory")?;
    let text =
        serde_json::to_string_pretty(&config_to_json(config)).context("Encode uts_view config")?;
    let tmp = dir.join("uts_view.json.tmp");
    std::fs::write(&tmp, text).context("Write uts_view config")?;
    std::fs::rename(&tmp, CONFIG_PATH).context("Install uts_view config")?;
    Ok(())
}

#[cfg(target_os = "android")]
fn ensure_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("Root is required for UTS View control");
    }
    Ok(())
}

/// Push the saved config to the kernel and set the feature to match
/// `config.enabled`. The kernel restores the real values on disable.
#[cfg(target_os = "android")]
fn apply_config(config: &Config) -> Result<()> {
    let wire = config_to_wire(config)?;
    ksucalls::set_uts_view_config(&wire)?;
    ksucalls::set_feature(
        crate::feature_id::FeatureId::UtsView as u32,
        u64::from(config.enabled),
    )?;
    Ok(())
}

/// Re-apply the saved config at boot. Best effort: a failure only warns,
/// it never fails the boot stage.
#[cfg(target_os = "android")]
pub fn boot_apply() {
    let config = match load_config() {
        Ok(config) => config,
        Err(error) => {
            warn!("Load UTS View config failed: {error:#}");
            return;
        }
    };
    if config == Config::default() {
        return;
    }
    if crate::utils::is_safe_mode() {
        warn!("safe mode, skip UTS View apply");
        return;
    }
    match apply_config(&config) {
        Ok(()) => info!("UTS View config applied"),
        Err(error) => warn!("Apply UTS View config failed: {error:#}"),
    }
}

#[cfg(target_os = "android")]
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Show whether UTS View is enabled, its mode, fields and targets
    Status,
    /// Set spoofed UTS fields (\"default\" restores the real value of that field)
    Set {
        /// spoofed sysname, or "default" to restore the real one
        #[arg(long)]
        sysname: Option<String>,
        /// spoofed nodename, or "default" to restore the real one
        #[arg(long)]
        nodename: Option<String>,
        /// spoofed release, or "default" to restore the real one
        #[arg(long)]
        release: Option<String>,
        /// spoofed version, or "default" to restore the real one
        #[arg(long)]
        version: Option<String>,
        /// spoofed machine, or "default" to restore the real one
        #[arg(long)]
        machine: Option<String>,
        /// spoofed domainname, or "default" to restore the real one
        #[arg(long)]
        domainname: Option<String>,
        /// mode: global (default) or selected
        #[arg(long)]
        mode: Option<String>,
        /// target app UIDs for selected mode (space or comma separated, replaces the list)
        #[arg(long, num_args = 0..)]
        targets: Vec<String>,
    },
    /// Enable UTS View with the saved config
    Enable,
    /// Disable UTS View (the saved config stays, the real values return)
    Disable,
    /// Disable UTS View and clear the saved config and kernel template
    Clear,
    /// Re-apply the saved config now
    Apply,
}

#[cfg(target_os = "android")]
fn update_config(update: impl FnOnce(&mut Config)) -> Result<()> {
    let mut config = load_config()?;
    update(&mut config);
    save_config(&config)
}

/// Apply one `--field` argument to a config slot: absent means unchanged,
/// `"default"` clears the field (restores the real value), anything else
/// sets it.
#[cfg(target_os = "android")]
fn apply_field(slot: &mut Option<String>, arg: Option<&String>) {
    match arg {
        None => {}
        Some(value) if value == "default" => *slot = None,
        Some(value) => *slot = Some(value.clone()),
    }
}

#[cfg(target_os = "android")]
fn parse_targets(values: &[String]) -> Result<Vec<u32>> {
    let mut targets = Vec::new();
    for value in values {
        for part in value.split([',', ' ']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let uid: u32 = part
                .parse()
                .with_context(|| format!("invalid uts target uid '{part}'"))?;
            targets.push(uid);
        }
    }
    validate_targets(&targets)?;
    Ok(targets)
}

#[cfg(target_os = "android")]
pub fn run(command: &Command) -> Result<()> {
    ensure_root()?;
    match command {
        Command::Status => {
            let enabled =
                ksucalls::get_feature(crate::feature_id::FeatureId::UtsView as u32)?.value != 0;
            // First line is the plain state the Manager parses.
            println!("{}", if enabled { "enabled" } else { "disabled" });
            let wire = ksucalls::get_uts_view_config()?;
            let kernel = config_from_wire(&wire);
            println!("mode: {}", kernel.mode.as_str());
            if let Some(release) = &kernel.release {
                println!("release: {release}");
            }
            if let Some(version) = &kernel.version {
                println!("version: {version}");
            }
            if let Some(sysname) = &kernel.sysname {
                println!("sysname: {sysname}");
            }
            if let Some(nodename) = &kernel.nodename {
                println!("nodename: {nodename}");
            }
            if let Some(machine) = &kernel.machine {
                println!("machine: {machine}");
            }
            if let Some(domainname) = &kernel.domainname {
                println!("domainname: {domainname}");
            }
            if !kernel.targets.is_empty() {
                let targets: Vec<String> = kernel.targets.iter().map(u32::to_string).collect();
                println!("targets: {}", targets.join(" "));
            }
            println!(
                "matched: {} discarded: {} unshare_failed: {}",
                wire.matched, wire.discarded, wire.unshare_failed
            );
            Ok(())
        }
        Command::Set {
            sysname,
            nodename,
            release,
            version,
            machine,
            domainname,
            mode,
            targets,
        } => {
            let mode = match mode {
                Some(mode) => Some(UtsMode::parse(mode)?),
                None => None,
            };
            let targets = if targets.is_empty() {
                None
            } else {
                Some(parse_targets(targets)?)
            };
            update_config(|config| {
                if let Some(mode) = mode {
                    config.mode = mode;
                }
                apply_field(&mut config.sysname, sysname.as_ref());
                apply_field(&mut config.nodename, nodename.as_ref());
                apply_field(&mut config.release, release.as_ref());
                apply_field(&mut config.version, version.as_ref());
                apply_field(&mut config.machine, machine.as_ref());
                apply_field(&mut config.domainname, domainname.as_ref());
                if let Some(targets) = targets {
                    config.targets = targets;
                }
            })?;
            let config = load_config()?;
            apply_config(&config)
        }
        Command::Enable => {
            update_config(|config| config.enabled = true)?;
            let config = load_config()?;
            if config_to_wire(&config)?.field_mask == 0 {
                bail!("no uts fields configured (use `ksud uts set` first)");
            }
            apply_config(&config)
        }
        Command::Disable => {
            update_config(|config| config.enabled = false)?;
            let config = load_config()?;
            apply_config(&config)
        }
        Command::Clear => {
            update_config(|config| {
                *config = Config::default();
            })?;
            let wire = config_to_wire(&Config::default())?;
            ksucalls::set_uts_view_config(&wire)?;
            ksucalls::set_feature(crate::feature_id::FeatureId::UtsView as u32, 0)?;
            let path = Path::new(CONFIG_PATH);
            if path.exists() {
                std::fs::remove_file(path).context("Remove uts_view config")?;
            }
            Ok(())
        }
        Command::Apply => {
            let config = load_config()?;
            apply_config(&config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "android")]
    use std::mem::offset_of;

    fn sample_config() -> Config {
        Config {
            mode: UtsMode::Global,
            sysname: Some("Linux".to_owned()),
            nodename: None,
            release: Some("4.19.325-st20-Maya-Kernel_Sienna-v2.9".to_owned()),
            version: Some("#1 SMP PREEMPT Thu Jan  1 00:00:00 UTC 1970".to_owned()),
            machine: Some("aarch64".to_owned()),
            domainname: None,
            targets: vec![10000, 10123],
            enabled: true,
        }
    }

    /// Android-only: the bindgen UAPI is only generated for the Android
    /// target, so this runs under `cargo test` for Android, never on host.
    /// It is compile-checked by `cargo ndk check --tests`.
    #[test]
    #[cfg(target_os = "android")]
    fn wire_size_matches_kernel_abi() {
        // Kernel-side static_assert in kernel/feature/uts_view.c: the ABI
        // is 972 bytes. If this fails, the kernel struct changed and the
        // bindgen layout drifted.
        assert_eq!(size_of::<ksu_uapi::ksu_uts_view_config>(), 972);
    }

    #[test]
    #[cfg(target_os = "android")]
    fn wire_field_offsets_match_kernel_abi() {
        assert_eq!(offset_of!(ksu_uapi::ksu_uts_view_config, field_mask), 0);
        assert_eq!(offset_of!(ksu_uapi::ksu_uts_view_config, sysname), 64);
        assert_eq!(offset_of!(ksu_uapi::ksu_uts_view_config, target_count), 456);
        assert_eq!(offset_of!(ksu_uapi::ksu_uts_view_config, target_uids), 460);
    }

    #[test]
    fn config_json_round_trip() {
        let config = sample_config();
        let value = config_to_json(&config);
        assert_eq!(config_from_json(&value), config);
    }

    #[test]
    #[cfg(target_os = "android")]
    fn config_wire_round_trip() {
        let config = sample_config();
        let wire = config_to_wire(&config).unwrap();
        let back = config_from_wire(&wire);
        assert_eq!(back, config);
    }

    #[test]
    fn field_too_long_is_rejected() {
        assert!(field_bytes(&"x".repeat(65)).is_err());
        assert!(field_bytes(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn target_validation_rejects_non_app_uids() {
        assert!(validate_targets(&[9999]).is_err());
        assert!(validate_targets(&[10000]).is_ok());
    }

    #[test]
    fn target_validation_rejects_duplicates_and_overflow() {
        assert!(validate_targets(&[10000, 10000]).is_err());
        assert!(validate_targets(&(10000..10000 + 129).collect::<Vec<u32>>()).is_err());
    }
}
