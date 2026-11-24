mod openvpn;
mod paths;
mod profiles;
mod tui;
mod ui;
mod vault;
mod waybar;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use profiles::{Profile, Store};
use vault::Vault;

#[derive(Parser)]
#[command(
    name = "warren",
    version,
    about = "OpenVPN profile manager: many tunnels at once, encrypted saved passwords",
    long_about = "OpenVPN profile manager: many tunnels at once, encrypted saved passwords.\n\nRun without a command to open the interactive TUI."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the interactive terminal UI (default)
    Tui,
    /// Import an .ovpn file as a new profile
    Import {
        file: PathBuf,
        /// Profile name (default: file name without extension)
        #[arg(short, long)]
        name: Option<String>,
        /// Ask for an OTP on every connect (auto-enabled if the config has `static-challenge`)
        #[arg(long)]
        otp: bool,
        /// Don't store username/password; ask on every connect instead
        #[arg(long)]
        no_save: bool,
    },
    /// List profiles and the state of running tunnels
    #[command(visible_aliases = ["ls", "status"])]
    List,
    /// Connect one or more profiles (they run in parallel)
    #[command(visible_alias = "up")]
    Connect {
        #[arg(required = true)]
        names: Vec<String>,
        /// Show openvpn log while connecting
        #[arg(short, long)]
        verbose: bool,
    },
    /// Disconnect profiles
    #[command(visible_alias = "down")]
    Disconnect {
        names: Vec<String>,
        /// Disconnect every running tunnel
        #[arg(short, long, conflicts_with = "names")]
        all: bool,
    },
    /// Change profile settings or stored credentials
    Edit {
        name: String,
        /// Enable/disable OTP prompt: --otp true | --otp false
        #[arg(long)]
        otp: Option<bool>,
        /// Set (or replace) saved username/password
        #[arg(long)]
        credentials: bool,
        /// Delete saved credentials (they will be asked on every connect)
        #[arg(long, conflicts_with = "credentials")]
        forget: bool,
    },
    /// Remove a profile and its saved credentials
    #[command(visible_alias = "rm")]
    Remove { name: String },
    /// Show the log of a running tunnel
    Logs {
        name: String,
        /// Number of lines
        #[arg(short = 'n', long, default_value_t = 40)]
        lines: usize,
    },
    /// Waybar custom module: prints JSON status lines (use with return-type: json)
    Waybar {
        /// Poll interval in seconds
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Print empty text (hides the module) when no VPN is connected
        #[arg(long)]
        hide_when_off: bool,
        /// Truncate the profile name to this many characters
        #[arg(long, default_value_t = 24)]
        max_length: usize,
    },
    /// Change the vault master password
    Passwd,
}

/// Terminal implementation of the connection UI.
struct TtyUi {
    verbose: bool,
    name: String,
    tail: RefCell<VecDeque<String>>,
}

impl TtyUi {
    fn new(name: &str, verbose: bool) -> Self {
        Self { verbose, name: name.to_string(), tail: RefCell::new(VecDeque::new()) }
    }

    fn print_tail(&self) {
        let tail = self.tail.borrow();
        if !tail.is_empty() {
            eprintln!("--- last openvpn log lines ---");
            for l in tail.iter() {
                eprintln!("  {l}");
            }
        }
    }
}

impl openvpn::Ui for TtyUi {
    fn ask(&self, msg: &str, secret: bool) -> Result<String> {
        let msg = format!("{msg}: ");
        if secret { Ok(ui::prompt_secret(&msg)?.to_string()) } else { ui::prompt_line(&msg) }
    }
    fn log(&self, line: &str) {
        if self.verbose {
            eprintln!("  [{}] {line}", self.name);
        }
        let mut t = self.tail.borrow_mut();
        if t.len() == 15 {
            t.pop_front();
        }
        t.push_back(line.to_string());
    }
    fn state(&self, state: &str) {
        if self.verbose {
            eprintln!("  [{}] state: {state}", self.name);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.cmd.unwrap_or(Cmd::Tui) {
        Cmd::Tui => tui::run(),
        Cmd::Import { file, name, otp, no_save } => cmd_import(&file, name, otp, no_save),
        Cmd::List => cmd_list(),
        Cmd::Connect { names, verbose } => cmd_connect(&names, verbose),
        Cmd::Disconnect { names, all } => cmd_disconnect(&names, all),
        Cmd::Edit { name, otp, credentials, forget } => cmd_edit(&name, otp, credentials, forget),
        Cmd::Remove { name } => cmd_remove(&name),
        Cmd::Logs { name, lines } => cmd_logs(&name, lines),
        Cmd::Waybar { interval, hide_when_off, max_length } => {
            waybar::run(&waybar::Options { interval, hide_when_off, max_length })
        }
        Cmd::Passwd => Vault::open().and_then(|mut v| v.change_master()).map(|_| {
            println!("Master password changed.");
        }),
    };
    if let Err(e) = res {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn cmd_import(file: &std::path::Path, name: Option<String>, otp: bool, no_save: bool) -> Result<()> {
    let (name, info) = profiles::import(file, name, otp)?;
    for w in &info.warnings {
        eprintln!("warning: {w}");
    }
    let mut store = Store::load()?;
    let profile = store.profiles.get_mut(&name).context("profile vanished")?;
    if no_save {
        profile.never_save = true;
    } else if profile.needs_secrets() {
        ask_otp_appended(profile)?;
        let cred = openvpn::prompt_secrets(&name, profile, &TtyUi::new(&name, false))?;
        let mut vault = Vault::open_or_create()?;
        vault.set(&name, cred);
        vault.save()?;
        profile.saved = true;
    }
    store.save()?;
    let profile = store.get(&name)?;

    println!("Imported '{name}'.");
    println!("  secrets: {}", describe_secrets(profile));
    println!(
        "  otp: {}",
        match (profile.otp, info.static_challenge) {
            (true, true) => "yes (static-challenge from config)",
            (true, false) => "yes (appended to password)",
            _ => "no (dynamic challenges are still handled)",
        }
    );
    Ok(())
}

/// For password-based profiles without static-challenge, ask whether an OTP is appended
/// to the password; if so only the static part gets saved and the OTP is asked on connect.
fn ask_otp_appended(p: &mut Profile) -> Result<()> {
    if (p.auth || !p.key_encrypted) && !p.static_challenge {
        p.otp = ui::confirm("Does the password end with an OTP code (password+OTP)?", p.otp)?;
    }
    Ok(())
}

fn describe_secrets(p: &Profile) -> String {
    let what = match (p.auth, p.key_encrypted) {
        (false, false) => return "none needed (certificate only)".into(),
        (true, false) => "username/password",
        (false, true) => "private key passphrase",
        (true, true) => "username/password + key passphrase",
    };
    let how = if p.saved { "saved (encrypted)" } else { "asked on connect" };
    format!("{what}, {how}")
}

fn cmd_list() -> Result<()> {
    let store = Store::load()?;
    let running = openvpn::running_names()?;
    if store.profiles.is_empty() && running.is_empty() {
        println!("No profiles. Import one with `warren import file.ovpn`.");
        return Ok(());
    }
    println!("{:<24} {:<12} {:<16} {:<16} {:<5} SECRETS", "NAME", "STATE", "VPN IP", "SERVER", "OTP");
    let mut names: Vec<&String> = store.profiles.keys().chain(running.iter()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let (state, ip, remote) = match openvpn::state(name) {
            Ok(Some(s)) => (s.state, s.local_ip, s.remote),
            Ok(None) => ("down".into(), String::new(), String::new()),
            Err(_) => ("busy".into(), String::new(), String::new()),
        };
        let (otp, secrets) = match store.profiles.get(name) {
            Some(p) => (if p.otp { "yes" } else { "no" }, describe_secrets(p)),
            None => ("-", "(profile removed)".into()),
        };
        println!("{name:<24} {state:<12} {ip:<16} {remote:<16} {otp:<5} {secrets}");
    }
    Ok(())
}

fn cmd_connect(names: &[String], verbose: bool) -> Result<()> {
    let mut store = Store::load()?;
    for n in names {
        store.get(n)?;
    }
    let mut vault: Option<Vault> = None;
    let mut failed = 0;
    for name in names {
        if let Err(e) = connect_one(&mut store, &mut vault, name, verbose) {
            eprintln!("✗ {name}: {e:#}");
            failed += 1;
        }
    }
    if failed > 0 {
        bail!("{failed} of {} connection(s) failed", names.len());
    }
    Ok(())
}

fn connect_one(store: &mut Store, vault: &mut Option<Vault>, name: &str, verbose: bool) -> Result<()> {
    let profile = store.get(name)?.clone();
    if openvpn::connect_running(name)?.is_some() {
        println!("• {name}: already running");
        return Ok(());
    }

    let saved = if profile.saved {
        if vault.is_none() {
            *vault = Some(Vault::open()?);
        }
        vault.as_ref().unwrap().get(name).cloned()
    } else {
        None
    };

    let ui = TtyUi::new(name, verbose);
    eprintln!("• {name}: starting openvpn...");
    let connected = match openvpn::connect(name, &profile, saved, &ui, true, |_| {}) {
        Ok(c) => c,
        Err(e) => {
            if !verbose {
                ui.print_tail();
            }
            return Err(e);
        }
    };
    let ip = &connected.ip;
    println!("✓ {name}: connected{}", if ip.is_empty() { String::new() } else { format!(" ({ip})") });

    if let Some(typed) = connected.typed {
        if !profile.never_save {
            let p = store.profiles.get_mut(name).context("profile vanished")?;
            if ui::confirm(&format!("Save the entered secret(s) for '{name}' in the encrypted vault?"), true)? {
                if vault.is_none() {
                    *vault = Some(Vault::open_or_create()?);
                }
                let v = vault.as_mut().unwrap();
                v.set(name, typed);
                v.save()?;
                p.saved = true;
                println!("  saved.");
            } else {
                p.never_save = true;
                println!("  not saved; won't ask again (use `warren edit {name} --credentials` later).");
            }
            store.save()?;
        }
    }
    Ok(())
}

fn cmd_disconnect(names: &[String], all: bool) -> Result<()> {
    let names: Vec<String> = if all { openvpn::running_names()? } else { names.to_vec() };
    if names.is_empty() {
        if all {
            println!("Nothing is running.");
            return Ok(());
        }
        bail!("give profile name(s) or --all");
    }
    for name in &names {
        if openvpn::stop(name)? {
            println!("✓ {name}: disconnected");
        } else {
            println!("• {name}: not running");
        }
    }
    Ok(())
}


fn cmd_edit(name: &str, otp: Option<bool>, credentials: bool, forget: bool) -> Result<()> {
    let mut store = Store::load()?;
    let mut profile = store.get(name)?.clone();
    if let Some(o) = otp {
        profile.otp = o;
    }
    if credentials {
        if otp.is_none() {
            ask_otp_appended(&mut profile)?;
        }
        let cred = openvpn::prompt_secrets(name, &profile, &TtyUi::new(name, false))?;
        let mut vault = Vault::open_or_create()?;
        if cred.has_auth() {
            profile.auth = true;
        }
        vault.set(name, cred);
        vault.save()?;
        profile.saved = true;
        profile.never_save = false;
    }
    if forget && profile.saved {
        let mut vault = Vault::open()?;
        vault.remove(name);
        vault.save()?;
        profile.saved = false;
    }
    store.profiles.insert(name.to_string(), profile.clone());
    store.save()?;
    println!("{name}: otp={}, secrets: {}", if profile.otp { "yes" } else { "no" }, describe_secrets(&profile));
    Ok(())
}

fn cmd_remove(name: &str) -> Result<()> {
    let store = Store::load()?;
    let profile = store.get(name)?;
    if openvpn::connect_running(name)?.is_some() {
        bail!("'{name}' is running, disconnect it first");
    }
    if profile.saved && Vault::exists()? {
        let mut vault = Vault::open()?;
        vault.remove(name);
        vault.save()?;
    }
    profiles::remove(name)?;
    println!("Removed '{name}'.");
    Ok(())
}

fn cmd_logs(name: &str, lines: usize) -> Result<()> {
    match openvpn::logs(name)? {
        Some(log) => {
            for l in log.iter().skip(log.len().saturating_sub(lines)) {
                println!("{l}");
            }
        }
        None => println!(
            "'{name}' is not running. Last log (owned by root): sudo cat {}",
            paths::log_path(name)?.display()
        ),
    }
    Ok(())
}
