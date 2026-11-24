//! Encrypted credential store.
//!
//! The file is JSON with an Argon2id salt, a random XChaCha20-Poly1305 nonce and the
//! ciphertext of a JSON map `profile name -> {username, password}`. The key is derived
//! from a master password that is never stored.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{paths, ui};

/// Secrets saved for one profile. Empty username = auth credentials not saved.
#[derive(Serialize, Deserialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// Passphrase of an encrypted private key.
    #[serde(default)]
    pub key_pass: Option<String>,
}

impl Credential {
    pub fn has_auth(&self) -> bool {
        !self.username.is_empty()
    }
    pub fn is_empty(&self) -> bool {
        !self.has_auth() && self.key_pass.is_none()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, 3 passes: a fraction of a second on a laptop.
        Self { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub struct Vault {
    path: PathBuf,
    kdf: KdfParams,
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    entries: BTreeMap<String, Credential>,
}

fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow!("bad kdf params: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

fn new_master_password() -> Result<Zeroizing<String>> {
    loop {
        let a = ui::prompt_secret("New master password: ")?;
        if a.is_empty() {
            eprintln!("Master password must not be empty.");
            continue;
        }
        let b = ui::prompt_secret("Repeat master password: ")?;
        if *a == *b {
            return Ok(a);
        }
        eprintln!("Passwords do not match, try again.");
    }
}

impl Vault {
    pub fn exists() -> Result<bool> {
        Ok(paths::vault_path()?.exists())
    }

    /// Creates a new empty vault protected by `password`.
    pub fn create(password: &str) -> Result<Self> {
        let path = paths::vault_path()?;
        let kdf = KdfParams::default();
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(password, &salt, kdf)?;
        let vault = Self { path, kdf, salt, key, entries: BTreeMap::new() };
        vault.save()?;
        Ok(vault)
    }

    /// Opens the vault, creating it (and asking for a new master password) if needed.
    pub fn open_or_create() -> Result<Self> {
        if Self::exists()? {
            return Self::open();
        }
        eprintln!("Creating encrypted password vault at {}", paths::vault_path()?.display());
        let pw = new_master_password()?;
        Self::create(&pw)
    }

    /// Opens the vault asking for the master password on the terminal.
    pub fn open() -> Result<Self> {
        for _ in 0..3 {
            let pw = ui::prompt_secret("Master password: ")?;
            if let Some(v) = Self::unlock(&pw)? {
                return Ok(v);
            }
            eprintln!("Wrong master password.");
        }
        bail!("too many failed attempts")
    }

    /// Decrypts the vault. Returns `Ok(None)` if the password is wrong.
    pub fn unlock(password: &str) -> Result<Option<Self>> {
        let path = paths::vault_path()?;
        let data = fs::read_to_string(&path)
            .with_context(|| format!("cannot read vault {}", path.display()))?;
        let vf: VaultFile = serde_json::from_str(&data).context("vault file is corrupted")?;
        if vf.version != 1 {
            bail!("unsupported vault version {}", vf.version);
        }
        let salt: [u8; 16] = B64
            .decode(&vf.salt)?
            .try_into()
            .map_err(|_| anyhow!("vault salt has wrong length"))?;
        let nonce = B64.decode(&vf.nonce)?;
        if nonce.len() != 24 {
            bail!("vault nonce has wrong length");
        }
        let ciphertext = B64.decode(&vf.ciphertext)?;

        let key = derive_key(password, &salt, vf.kdf)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
        let Ok(plain) = cipher.decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref()) else {
            return Ok(None);
        };
        let plain = Zeroizing::new(plain);
        let entries = serde_json::from_slice(&plain).context("vault content is corrupted")?;
        Ok(Some(Self { path, kdf: vf.kdf, salt, key, entries }))
    }

    pub fn save(&self) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.entries)?);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plain.as_ref())
            .map_err(|_| anyhow!("encryption failed"))?;
        let vf = VaultFile {
            version: 1,
            kdf: self.kdf,
            salt: B64.encode(self.salt),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        };
        paths::write_private(&self.path, &serde_json::to_vec_pretty(&vf)?)
    }

    pub fn get(&self, name: &str) -> Option<&Credential> {
        self.entries.get(name)
    }

    pub fn set(&mut self, name: &str, cred: Credential) {
        self.entries.insert(name.to_string(), cred);
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    pub fn change_master(&mut self) -> Result<()> {
        let pw = new_master_password()?;
        OsRng.fill_bytes(&mut self.salt);
        self.kdf = KdfParams::default();
        self.key = derive_key(&pw, &self.salt, self.kdf)?;
        self.save()
    }
}
