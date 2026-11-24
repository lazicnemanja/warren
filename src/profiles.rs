use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::paths;

/// Non-secret profile metadata (secrets live in the vault).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Profile {
    /// Server requires username/password (`auth-user-pass`).
    pub auth: bool,
    /// Secrets are stored in the encrypted vault (otherwise prompted on connect).
    pub saved: bool,
    /// Ask for an OTP on connect (static-challenge if the config has it, else appended to password).
    pub otp: bool,
    /// User declined saving; don't offer it again after connecting.
    #[serde(default)]
    pub never_save: bool,
    /// Private key is passphrase protected (detected from the config on load).
    #[serde(skip)]
    pub key_encrypted: bool,
    /// Config has `static-challenge`: OTP is asked separately, never part of the password.
    #[serde(skip)]
    pub static_challenge: bool,
}

impl Profile {
    /// OTP is typed at connect and appended to the saved (static) password.
    pub fn otp_appended(&self) -> bool {
        self.otp && !self.static_challenge
    }

    /// Whether connecting needs anything typed in (password or key passphrase).
    pub fn needs_secrets(&self) -> bool {
        self.auth || self.key_encrypted
    }

    pub fn describe_secrets(&self) -> &'static str {
        match (self.needs_secrets(), self.saved) {
            (false, _) => "none",
            (true, true) => "saved",
            (true, false) => "ask",
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Store {
    pub profiles: BTreeMap<String, Profile>,
}

impl Store {
    pub fn load() -> Result<Self> {
        let path = paths::profiles_file()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(&path)?;
        let mut store: Self =
            serde_json::from_str(&data).with_context(|| format!("cannot parse {}", path.display()))?;
        for (name, p) in store.profiles.iter_mut() {
            let info = inspect(name);
            p.key_encrypted = info.encrypted_key;
            p.static_challenge = info.static_challenge;
        }
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        paths::write_private(&paths::profiles_file()?, &serde_json::to_vec_pretty(self)?)
    }

    pub fn get(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .get(name)
            .with_context(|| format!("unknown profile '{name}' (see `warren list`)"))
    }
}

/// What we learn from scanning an .ovpn file.
#[derive(Default, Debug)]
pub struct OvpnInfo {
    pub needs_auth: bool,
    pub static_challenge: bool,
    /// Inline `<key>` block is encrypted.
    pub encrypted_key: bool,
    /// File given by the `key` directive, if not inline.
    pub key_file: Option<String>,
    /// Files referenced by directives like `ca`, `cert`, `key` (not inline).
    pub files: Vec<String>,
    pub warnings: Vec<String>,
}

fn is_encrypted_pem(text: &str) -> bool {
    text.contains("ENCRYPTED PRIVATE KEY") || text.contains("Proc-Type: 4,ENCRYPTED")
}

/// Scans the installed profile `name` (also checks a separate key file for encryption).
pub fn inspect(name: &str) -> OvpnInfo {
    let Ok(dir) = paths::profile_dir(name) else { return OvpnInfo::default() };
    let Ok(text) = fs::read_to_string(dir.join("config.ovpn")) else { return OvpnInfo::default() };
    let mut info = analyze(&text);
    if !info.encrypted_key {
        info.encrypted_key = info
            .key_file
            .as_ref()
            .and_then(|f| fs::read_to_string(dir.join(f)).ok())
            .is_some_and(|k| is_encrypted_pem(&k));
    }
    info
}

const FILE_DIRECTIVES: &[&str] = &[
    "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "crl-verify", "dh",
    "extra-certs", "secret",
];

pub fn analyze(text: &str) -> OvpnInfo {
    let mut info = OvpnInfo::default();
    let mut in_block: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(tag) = &in_block {
            if t.eq_ignore_ascii_case(&format!("</{tag}>")) {
                in_block = None;
            } else if tag == "key" && is_encrypted_pem(t) {
                info.encrypted_key = true;
            }
            continue;
        }
        if t.starts_with('<') && t.ends_with('>') && !t.starts_with("</") {
            in_block = Some(t[1..t.len() - 1].to_string());
            continue;
        }
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        let mut it = t.split_whitespace();
        let Some(directive) = it.next() else { continue };
        match directive {
            "auth-user-pass" => info.needs_auth = true,
            "static-challenge" => info.static_challenge = true,
            d if FILE_DIRECTIVES.contains(&d) => {
                if let Some(arg) = it.next() {
                    let arg = arg.trim_matches(['"', '\'']);
                    if arg != "[inline]" {
                        info.files.push(arg.to_string());
                        if d == "key" {
                            info.key_file = Some(arg.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    info
}

/// Profile name derived from the file name (`My VPN.ovpn` -> `My-VPN`).
pub fn default_name(file: &Path) -> String {
    file.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vpn")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' })
        .collect()
}

/// Copies the .ovpn (and referenced files) into the profile dir and registers the profile
/// without saved credentials. Returns the profile name and what was found in the config.
/// Warnings (e.g. absolute paths left as is) are returned in `OvpnInfo::warnings`.
pub fn import(file: &Path, name: Option<String>, otp: bool) -> Result<(String, OvpnInfo)> {
    let text = fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let name = name.unwrap_or_else(|| default_name(file));
    paths::validate_name(&name)?;

    let mut store = Store::load()?;
    if store.profiles.contains_key(&name) {
        bail!("profile '{name}' already exists");
    }

    let mut info = analyze(&text);
    let dir = paths::profile_dir(&name)?;
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    paths::ensure_private_dir(&dir)?;
    if let Err(e) = copy_profile_files(file, &text, &mut info, &dir) {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }

    let profile = Profile {
        auth: info.needs_auth,
        saved: false,
        otp: otp || info.static_challenge,
        never_save: false,
        key_encrypted: false,
        static_challenge: info.static_challenge,
    };
    store.profiles.insert(name.clone(), profile);
    store.save()?;
    // Also covers a key in a separate (now copied) file.
    info.encrypted_key = inspect(&name).encrypted_key;
    Ok((name, info))
}

fn copy_profile_files(src: &Path, text: &str, info: &mut OvpnInfo, dir: &Path) -> Result<()> {
    let base = src.parent().unwrap_or(Path::new("."));
    for f in info.files.clone() {
        let p = Path::new(&f);
        if p.is_absolute() {
            info.warnings.push(format!("config references absolute path {f}, left as is"));
            continue;
        }
        if p.components().any(|c| c == Component::ParentDir) {
            info.warnings.push(format!("config references {f} outside its directory; fix the path manually"));
            continue;
        }
        let dst = dir.join(p);
        if let Some(parent) = dst.parent() {
            paths::ensure_private_dir(parent)?;
        }
        fs::copy(base.join(p), &dst).with_context(|| format!("cannot copy referenced file {f}"))?;
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o600))?;
    }
    paths::write_private(&dir.join("config.ovpn"), text.as_bytes())
}

/// Deletes the profile files and its metadata (not the vault entry).
pub fn remove(name: &str) -> Result<()> {
    let mut store = Store::load()?;
    let dir = paths::profile_dir(name)?;
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    store.profiles.remove(name);
    store.save()
}
