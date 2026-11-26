//! Minimal SUSFS userspace driver.
//!
//! Pushes configuration to the kernel-side SUSFS (v2.4.0) through the
//! reboot-syscall control ABI (`reboot(0xDEADBEEF, 0xFAFAFAFA, cmd, payload)`).
//! This module never installs SUSFS and never patches the kernel: it only
//! talks to a kernel that already carries it (for example the sienna 4.19
//! tree, `fs/susfs.c`, whose `include/linux/susfs.h` defines the wire
//! layouts used here).
//!
//! Every setter applies live and records the value in `susfs.json` under the
//! ksud working directory, so `susfs apply` (run at boot) can re-apply the
//! same configuration after a reboot. The stored config is a plain JSON
//! object. There is no ownership tracking and no fail-closed state machine;
//! see the FinaSU `susfs/` module if that is ever needed.

use anyhow::{Context, Result, bail};
use const_format::concatcp;
use serde_json::{Value, json};
use std::path::Path;

#[cfg(target_os = "android")]
use clap::Subcommand;
#[cfg(target_os = "android")]
use log::{info, warn};

/// Magic the kernel expects as the second reboot argument for SUSFS.
const SUSFS_MAGIC: u32 = 0xfafa_fafa;
/// First reboot magic, shared with the driver install path.
const KSU_INSTALL_MAGIC1: u32 = 0xdead_beef;

/// Sentinel the kernel never writes: if `err` still holds this value after
/// the syscall, the command was not handled (no SUSFS in the running kernel).
const ERR_NOT_HANDLED: i32 = 126;

const CMD_SUSFS_ADD_SUS_PATH: u32 = 0x55550;
const CMD_SUSFS_ADD_SUS_PATH_LOOP: u32 = 0x55553;
const CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS: u32 = 0x55561;
const CMD_SUSFS_SET_UNAME: u32 = 0x55590;
const CMD_SUSFS_ENABLE_LOG: u32 = 0x555a0;
const CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: u32 = 0x555b0;
const CMD_SUSFS_SHOW_VERSION: u32 = 0x555e1;
const CMD_SUSFS_SHOW_ENABLED_FEATURES: u32 = 0x555e2;
const CMD_SUSFS_SHOW_VARIANT: u32 = 0x555e3;
const CMD_SUSFS_SET_PRIORITY_UID_FILTER: u32 = 0x60030;

const SUSFS_MAX_LEN_PATHNAME: usize = 256;
const SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE: usize = 8192;
const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
const SUSFS_APP_STR_BUF_SIZE: usize = 65535;
/// `__NEW_UTS_LEN + 1`: 64 usable characters plus the NUL terminator.
const UTS_LEN: usize = 65;

#[cfg(target_os = "android")]
const CONFIG_PATH: &str = concatcp!(crate::defs::WORKING_DIR, "susfs.json");

/// Wire layout shared by the path, cmdline, features, version, variant and
/// app-string payloads: an N-byte buffer followed by the kernel-written
/// error field. Matches `st_susfs_*` in `include/linux/susfs.h`; keep the
/// native C alignment, including the trailing error sentinel.
#[repr(C)]
pub struct Text<const N: usize> {
    pub text: [u8; N],
    pub err: i32,
}

#[cfg(target_os = "android")]
impl<const N: usize> Text<N> {
    pub const fn empty() -> Self {
        Self {
            text: [0; N],
            err: ERR_NOT_HANDLED,
        }
    }
}

/// Wire layout for the boolean toggles (`hide_mounts`, `enable_log`).
#[repr(C)]
pub struct Toggle {
    pub enabled: bool,
    pub err: i32,
}

#[cfg(target_os = "android")]
impl Toggle {
    pub const fn new(enabled: bool) -> Self {
        Self {
            enabled,
            err: ERR_NOT_HANDLED,
        }
    }
}

/// Wire layout for `CMD_SUSFS_SET_UNAME` (`struct st_susfs_uname`).
#[repr(C)]
pub struct Uname {
    pub release: [u8; UTS_LEN],
    pub version: [u8; UTS_LEN],
    pub err: i32,
}

pub fn bytes<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() >= N || value.as_bytes().contains(&0) {
        bail!("field exceeds SUSFS buffer length");
    }
    let mut result = [0; N];
    result[..value.len()].copy_from_slice(value.as_bytes());
    Ok(result)
}

pub fn string(value: &[u8]) -> Option<String> {
    let end = value.iter().position(|c| *c == 0)?;
    std::str::from_utf8(&value[..end]).ok().map(str::to_owned)
}

#[cfg(target_os = "android")]
trait HasErr {
    fn err(&self) -> i32;
}

#[cfg(target_os = "android")]
impl<const N: usize> HasErr for Text<N> {
    fn err(&self) -> i32 {
        self.err
    }
}

#[cfg(target_os = "android")]
impl HasErr for Toggle {
    fn err(&self) -> i32 {
        self.err
    }
}

#[cfg(target_os = "android")]
impl HasErr for Uname {
    fn err(&self) -> i32 {
        self.err
    }
}

/// Raw control call. The syscall returns 0 by design; the kernel reports
/// success or failure through the payload's `err` field, so callers must use
/// [`call_checked`] or [`query_text`] instead of this.
#[cfg(target_os = "android")]
fn call<T>(command: u32, payload: &mut T) {
    // Invalid reboot magics are rejected by stock kernels; never use real
    // reboot magics. The payload stays owned and live until the syscall has
    // returned.
    unsafe {
        libc::syscall(
            libc::SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            command,
            std::ptr::from_mut(payload),
        );
    }
}

#[cfg(target_os = "android")]
fn call_checked<T: HasErr>(command: u32, payload: &mut T) -> Result<()> {
    call(command, payload);
    match payload.err() {
        0 => Ok(()),
        ERR_NOT_HANDLED => bail!("kernel did not handle SUSFS command 0x{command:x} (no SUSFS?)"),
        err => bail!("SUSFS returned error {err} for command 0x{command:x}"),
    }
}

/// Read-back query: `Ok(None)` when the kernel did not handle the command.
#[cfg(target_os = "android")]
fn query_text<const N: usize>(command: u32) -> Result<Option<String>> {
    let mut payload = Text::<N>::empty();
    call(command, &mut payload);
    match payload.err {
        0 => Ok(string(&payload.text)),
        ERR_NOT_HANDLED => Ok(None),
        err => bail!("SUSFS returned error {err} for command 0x{command:x}"),
    }
}

#[cfg(target_os = "android")]
fn ensure_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("Root is required for SUSFS control");
    }
    Ok(())
}

fn parse_on_off(value: &str) -> Result<bool> {
    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "on" | "true" | "1" | "yes" => Ok(true),
        "off" | "false" | "0" | "no" => Ok(false),
        _ => bail!("expected on/off, got '{value}'"),
    }
}

fn split_packages(packages: &[String]) -> Vec<String> {
    packages
        .iter()
        .flat_map(|item| item.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Persistent SUSFS configuration, re-applied at boot by [`boot_apply`].
/// `priority_uid_packages` is `None` while never set (skip it on apply) and
/// `Some` once the user sets it; `Some(vec![])` clears the kernel filter.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
    pub sus_paths: Vec<String>,
    pub uname: Option<(String, String)>,
    pub cmdline: Option<String>,
    pub priority_uid_packages: Option<Vec<String>>,
    pub hide_mounts: bool,
    pub log: bool,
}

fn config_to_json(config: &Config) -> Value {
    json!({
        "version": 1,
        "sus_paths": config.sus_paths,
        "uname": config.uname.as_ref().map(|(release, version)| json!({"release": release, "version": version})),
        "cmdline": config.cmdline,
        "priority_uid_packages": config.priority_uid_packages,
        "hide_mounts": config.hide_mounts,
        "log": config.log,
    })
}

fn config_from_json(value: &Value) -> Config {
    let mut config = Config::default();
    if let Some(paths) = value.get("sus_paths").and_then(Value::as_array) {
        config.sus_paths = paths
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    if let Some(uname) = value.get("uname")
        && let (Some(release), Some(version)) = (
            uname.get("release").and_then(Value::as_str),
            uname.get("version").and_then(Value::as_str),
        )
    {
        config.uname = Some((release.to_owned(), version.to_owned()));
    }
    if let Some(cmdline) = value.get("cmdline").and_then(Value::as_str) {
        config.cmdline = Some(cmdline.to_owned());
    }
    if let Some(packages) = value.get("priority_uid_packages").and_then(Value::as_array) {
        config.priority_uid_packages = Some(
            packages
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        );
    }
    config.hide_mounts = value
        .get("hide_mounts")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    config.log = value.get("log").and_then(Value::as_bool).unwrap_or(false);
    config
}

#[cfg(target_os = "android")]
pub fn load_config() -> Result<Config> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("Read {CONFIG_PATH}"))?;
    let value: Value = serde_json::from_str(&text).context("Parse susfs config")?;
    Ok(config_from_json(&value))
}

#[cfg(target_os = "android")]
pub fn save_config(config: &Config) -> Result<()> {
    let dir = Path::new(crate::defs::WORKING_DIR);
    std::fs::create_dir_all(dir).context("Create ksud working directory")?;
    let text =
        serde_json::to_string_pretty(&config_to_json(config)).context("Encode susfs config")?;
    let tmp = dir.join("susfs.json.tmp");
    std::fs::write(&tmp, text).context("Write susfs config")?;
    std::fs::rename(&tmp, CONFIG_PATH).context("Install susfs config")?;
    Ok(())
}

#[cfg(target_os = "android")]
fn add_sus_path_live(path: &str, loop_path: bool) -> Result<()> {
    let mut payload = Text::<SUSFS_MAX_LEN_PATHNAME> {
        text: bytes(path).context("sus_path exceeds 256 bytes")?,
        err: ERR_NOT_HANDLED,
    };
    let command = if loop_path {
        CMD_SUSFS_ADD_SUS_PATH_LOOP
    } else {
        CMD_SUSFS_ADD_SUS_PATH
    };
    call_checked(command, &mut payload)
}

#[cfg(target_os = "android")]
fn set_uname_live(release: &str, version: &str) -> Result<()> {
    let mut payload = Uname {
        release: bytes(release).context("uname release exceeds 64 bytes")?,
        version: bytes(version).context("uname version exceeds 64 bytes")?,
        err: ERR_NOT_HANDLED,
    };
    call_checked(CMD_SUSFS_SET_UNAME, &mut payload)
}

#[cfg(target_os = "android")]
fn set_cmdline_live(cmdline: &str) -> Result<()> {
    if cmdline.is_empty() {
        bail!("fake cmdline must not be empty (kernel rejects it)");
    }
    let mut payload = Text::<SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE> {
        text: bytes(cmdline).context("cmdline exceeds 8191 bytes")?,
        err: ERR_NOT_HANDLED,
    };
    call_checked(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, &mut payload)
}

#[cfg(target_os = "android")]
fn set_priority_uids_live(packages: &[String]) -> Result<()> {
    let joined = packages.join(",");
    let mut payload = Text::<SUSFS_APP_STR_BUF_SIZE> {
        text: bytes(&joined).context("package list exceeds 65534 bytes")?,
        err: ERR_NOT_HANDLED,
    };
    call_checked(CMD_SUSFS_SET_PRIORITY_UID_FILTER, &mut payload)
}

#[cfg(target_os = "android")]
fn set_toggle_live(command: u32, enabled: bool) -> Result<()> {
    let mut payload = Toggle::new(enabled);
    call_checked(command, &mut payload)
}

#[cfg(target_os = "android")]
pub struct Detection {
    pub version: Option<String>,
    pub variant: Option<String>,
    pub features: Vec<String>,
}

#[cfg(target_os = "android")]
fn detect() -> Result<Detection> {
    let version = query_text::<16>(CMD_SUSFS_SHOW_VERSION)?;
    let variant = query_text::<16>(CMD_SUSFS_SHOW_VARIANT)?;
    let features = query_text::<SUSFS_ENABLED_FEATURES_SIZE>(CMD_SUSFS_SHOW_ENABLED_FEATURES)?
        .map(|text| {
            text.lines()
                .map(str::to_owned)
                .filter(|line| !line.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Ok(Detection {
        version,
        variant,
        features,
    })
}

#[cfg(target_os = "android")]
pub fn apply_config(config: &Config) -> Result<()> {
    for path in &config.sus_paths {
        add_sus_path_live(path, false).with_context(|| format!("Apply sus_path {path}"))?;
        info!("susfs: added sus_path {path}");
    }
    if let Some((release, version)) = &config.uname {
        set_uname_live(release, version).context("Apply uname spoof")?;
        info!("susfs: set uname release={release} version={version}");
    }
    if let Some(cmdline) = &config.cmdline {
        set_cmdline_live(cmdline).context("Apply cmdline spoof")?;
        info!("susfs: set cmdline spoof");
    }
    if let Some(packages) = &config.priority_uid_packages {
        set_priority_uids_live(packages).context("Apply priority UID filter")?;
        info!("susfs: set priority UID packages: {}", packages.join(","));
    }
    set_toggle_live(CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS, config.hide_mounts)
        .context("Apply hide_mounts")?;
    set_toggle_live(CMD_SUSFS_ENABLE_LOG, config.log).context("Apply log")?;
    Ok(())
}

/// Re-apply the saved config at boot. Best effort: a failure only warns,
/// it never fails the boot stage.
#[cfg(target_os = "android")]
pub fn boot_apply() {
    let config = match load_config() {
        Ok(config) => config,
        Err(error) => {
            warn!("Load SUSFS config failed: {error:#}");
            return;
        }
    };
    if config == Config::default() {
        return;
    }
    if crate::utils::is_safe_mode() {
        warn!("safe mode, skip SUSFS apply");
        return;
    }
    match apply_config(&config) {
        Ok(()) => info!("SUSFS config applied"),
        Err(error) => warn!("Apply SUSFS config failed: {error:#}"),
    }
}

#[cfg(target_os = "android")]
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Show the kernel SUSFS version, variant, enabled features and the saved config
    Status,
    /// Add a path to the sus_path list (applies live and saves it)
    AddPath {
        /// path to hide from non-root processes
        path: String,
    },
    /// Add a path to the sus_path loop list (applies live and saves it)
    AddPathLoop {
        /// path to hide from non-root processes
        path: String,
    },
    /// Set the spoofed uname release and version ("default" resets that field)
    SetUname {
        /// spoofed release string, or "default" to restore the real one
        release: String,
        /// spoofed version string, or "default" to restore the real one
        #[arg(default_value = "default")]
        version: String,
    },
    /// Set the fake /proc/cmdline (or bootconfig) string
    SetCmdline {
        /// fake cmdline string (must not be empty)
        cmdline: String,
    },
    /// Set the priority UID filter from package names (no names clears it)
    SetPriorityUids {
        /// package names (space or comma separated)
        #[arg(num_args = 0..)]
        packages: Vec<String>,
    },
    /// Hide sus mounts from non-root processes
    HideMounts {
        /// on/off
        enabled: String,
    },
    /// Enable or disable SUSFS kernel logging
    Log {
        /// on/off
        enabled: String,
    },
    /// Re-apply the saved config now
    Apply,
}

#[cfg(target_os = "android")]
fn update_config(update: impl FnOnce(&mut Config)) -> Result<()> {
    let mut config = load_config()?;
    update(&mut config);
    save_config(&config)
}

#[cfg(target_os = "android")]
pub fn run(command: Command) -> Result<()> {
    ensure_root()?;
    match command {
        Command::Status => {
            let detection = detect()?;
            match detection.version {
                Some(version) => {
                    println!("SUSFS version: {version}");
                    if let Some(variant) = detection.variant {
                        println!("variant: {variant}");
                    }
                    if detection.features.is_empty() {
                        println!("features: (none reported)");
                    } else {
                        println!("features:");
                        for feature in &detection.features {
                            println!("  {feature}");
                        }
                    }
                }
                None => {
                    println!("SUSFS: not detected (kernel did not answer control commands)");
                }
            }
            let config = load_config()?;
            println!(
                "saved sus_paths: {}",
                if config.sus_paths.is_empty() {
                    "(none)".to_owned()
                } else {
                    config.sus_paths.join(", ")
                }
            );
            match &config.uname {
                Some((release, version)) => {
                    println!("saved uname: release={release} version={version}");
                }
                None => println!("saved uname: (not set)"),
            }
            match &config.cmdline {
                Some(cmdline) => println!("saved cmdline: {cmdline}"),
                None => println!("saved cmdline: (not set)"),
            }
            match &config.priority_uid_packages {
                Some(packages) => println!(
                    "saved priority UID packages: {}",
                    if packages.is_empty() {
                        "(cleared)".to_owned()
                    } else {
                        packages.join(", ")
                    }
                ),
                None => println!("saved priority UID packages: (not set)"),
            }
            println!("saved hide_mounts: {}", config.hide_mounts);
            println!("saved log: {}", config.log);
        }
        Command::AddPath { path } => {
            add_sus_path_live(&path, false)?;
            update_config(|config| {
                if !config.sus_paths.contains(&path) {
                    config.sus_paths.push(path.clone());
                }
            })?;
            println!("added sus_path {path}");
        }
        Command::AddPathLoop { path } => {
            add_sus_path_live(&path, true)?;
            update_config(|config| {
                if !config.sus_paths.contains(&path) {
                    config.sus_paths.push(path.clone());
                }
            })?;
            println!("added sus_path (loop) {path}");
        }
        Command::SetUname { release, version } => {
            set_uname_live(&release, &version)?;
            update_config(|config| config.uname = Some((release, version)))?;
            println!("uname spoof set");
        }
        Command::SetCmdline { cmdline } => {
            set_cmdline_live(&cmdline)?;
            update_config(|config| config.cmdline = Some(cmdline))?;
            println!("cmdline spoof set");
        }
        Command::SetPriorityUids { packages } => {
            let packages = split_packages(&packages);
            set_priority_uids_live(&packages)?;
            let joined = packages.join(",");
            update_config(|config| config.priority_uid_packages = Some(packages))?;
            println!("priority UID packages set: {joined}");
        }
        Command::HideMounts { enabled } => {
            let enabled = parse_on_off(&enabled)?;
            set_toggle_live(CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS, enabled)?;
            update_config(|config| config.hide_mounts = enabled)?;
            println!("hide_mounts: {}", if enabled { "on" } else { "off" });
        }
        Command::Log { enabled } => {
            let enabled = parse_on_off(&enabled)?;
            set_toggle_live(CMD_SUSFS_ENABLE_LOG, enabled)?;
            update_config(|config| config.log = enabled)?;
            println!("log: {}", if enabled { "on" } else { "off" });
        }
        Command::Apply => {
            let config = load_config()?;
            apply_config(&config)?;
            println!("SUSFS config applied");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_layouts_match_susfs_h() {
        assert_eq!(std::mem::offset_of!(Text<65535>, err), 65536);
        assert_eq!(std::mem::size_of::<Text<65535>>(), 65540);
        assert_eq!(std::mem::size_of::<Text<256>>(), 260);
        assert_eq!(std::mem::size_of::<Text<16>>(), 20);
        assert_eq!(std::mem::offset_of!(Text<8192>, err), 8192);
        assert_eq!(std::mem::size_of::<Toggle>(), 8);
        assert_eq!(std::mem::offset_of!(Uname, err), 132);
        assert_eq!(std::mem::size_of::<Uname>(), 136);
    }

    #[test]
    fn strings_are_bounded_and_terminated() {
        assert!(bytes::<16>(&"x".repeat(16)).is_err());
        assert!(bytes::<16>("a\0b").is_err());
        assert_eq!(bytes::<16>("abc").unwrap(), {
            let mut expected = [0; 16];
            expected[..3].copy_from_slice(b"abc");
            expected
        });
        assert!(string(&[b'x'; 16]).is_none());
        assert_eq!(string(b"v2.4.0\0junk").as_deref(), Some("v2.4.0"));
    }

    #[test]
    fn on_off_parsing() {
        assert!(parse_on_off("on").unwrap());
        assert!(parse_on_off("TRUE").unwrap());
        assert!(parse_on_off("1").unwrap());
        assert!(!parse_on_off("off").unwrap());
        assert!(!parse_on_off("False").unwrap());
        assert!(!parse_on_off("0").unwrap());
        assert!(parse_on_off("maybe").is_err());
    }

    #[test]
    fn package_lists_split_on_commas_and_spaces() {
        assert_eq!(
            split_packages(&["com.a,com.b".to_owned(), "com.c".to_owned()]),
            vec!["com.a", "com.b", "com.c"]
        );
        assert_eq!(
            split_packages(&["com.a,, com.b ,".to_owned()]),
            vec!["com.a", "com.b"]
        );
        assert_eq!(split_packages(&[]), Vec::<String>::new());
    }

    #[test]
    fn config_round_trip() {
        let config = Config {
            sus_paths: vec!["/data/adb/modules".to_owned()],
            uname: Some(("4.19.325-g32267489".to_owned(), "default".to_owned())),
            cmdline: Some("androidboot.foo=bar".to_owned()),
            priority_uid_packages: Some(vec!["com.example.app".to_owned()]),
            hide_mounts: true,
            log: false,
        };
        let restored = config_from_json(&config_to_json(&config));
        assert_eq!(restored, config);
        assert_eq!(config_from_json(&Value::Null), Config::default());
        assert_eq!(
            config_from_json(&json!({"priority_uid_packages": []})).priority_uid_packages,
            Some(vec![])
        );
    }
}
