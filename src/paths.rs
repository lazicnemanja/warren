use std::ffi::CStr;
use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The project used to be called `rust-vpn`: move an old directory to the new name once.
fn migrate(base: &Path, old: &str, new: &str) {
    let (old, new) = (base.join(old), base.join(new));
    if old.is_dir() && !new.exists() {
        let _ = fs::rename(&old, &new);
    }
}

/// ~/.config/warren
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("cannot determine config directory")?;
    migrate(&base, "rust-vpn", "warren");
    Ok(base.join("warren"))
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("vault.json"))
}

pub fn profiles_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("profiles.json"))
}

/// Directory holding config.ovpn (and referenced cert/key files) for a profile.
pub fn profile_dir(name: &str) -> Result<PathBuf> {
    Ok(config_dir()?.join("profiles").join(name))
}

/// $XDG_RUNTIME_DIR/warren — sockets and logs of running tunnels (tmpfs, private).
pub fn runtime_dir() -> Result<PathBuf> {
    let dir = match dirs::runtime_dir() {
        Some(d) => {
            // Sockets of tunnels started by the old version keep working after the move.
            migrate(&d, "rust-vpn", "warren");
            d.join("warren")
        }
        None => PathBuf::from(format!("/tmp/warren-{}", unsafe { libc::geteuid() })),
    };
    ensure_private_dir(&dir)?;
    Ok(dir)
}

pub fn socket_path(name: &str) -> Result<PathBuf> {
    Ok(runtime_dir()?.join(format!("{name}.sock")))
}

pub fn log_path(name: &str) -> Result<PathBuf> {
    Ok(runtime_dir()?.join(format!("{name}.log")))
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))
}

/// Atomically write a file readable only by the current user.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn current_user() -> Result<String> {
    unsafe {
        let pw = libc::getpwuid(libc::geteuid());
        if pw.is_null() {
            bail!("cannot determine current user name");
        }
        Ok(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || name.starts_with('.')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid profile name '{name}' (allowed: letters, digits, '-', '_', '.')");
    }
    Ok(())
}
