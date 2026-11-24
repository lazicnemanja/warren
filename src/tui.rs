//! Interactive terminal UI.
//!
//! The UI thread owns all state. Connections run in worker threads that report progress and
//! ask questions (sudo password, OTP, ...) through a channel; questions become modal prompts.
//! A refresher thread polls the state of running tunnels and the log of the selected one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;
use zeroize::Zeroizing;

use crate::openvpn::{self, Connected, TunnelState, Ui};
use crate::profiles::{self, Store};
use crate::vault::{Credential, Vault};

const MAX_LOG_LINES: usize = 500;
const REFRESH: Duration = Duration::from_millis(1500);

enum AppEvent {
    Prompt { name: String, msg: String, secret: bool, reply: Sender<Option<String>> },
    Log(String, String),
    Phase(String, String),
    Started(String, UnixStream),
    Connected(String, Result<Connected, String>),
    Stopped(String, Result<bool, String>),
    States(HashMap<String, TunnelState>),
    Logs(String, Vec<String>),
}

/// State the refresher thread needs to see.
#[derive(Default)]
struct Shared {
    names: Vec<String>,
    busy: HashSet<String>,
    selected: Option<String>,
}

/// Something to do once the vault is unlocked.
enum After {
    Connect(String),
    SaveCreds(String, Credential),
    Forget(String),
    Delete(String),
}

enum Purpose {
    Worker(String, Sender<Option<String>>),
    Master(After),
    NewMaster(After),
    RepeatMaster(After, Zeroizing<String>),
    ImportPath,
    ImportName(PathBuf),
    CredUser(String),
    CredPass(String, String),
    /// Key passphrase, with username/password entered just before (if any).
    KeyPass(String, Option<(String, String)>),
}

enum ConfirmPurpose {
    Delete(String),
    Quit,
    SaveTyped(String, Credential),
    /// Answer sets `otp`; then the password is asked (profile, username).
    OtpAppended(String, String),
}

enum Modal {
    Input { title: String, value: String, secret: bool, purpose: Purpose },
    Confirm { text: String, purpose: ConfirmPurpose },
}

struct WorkerUi {
    name: String,
    tx: Sender<AppEvent>,
}

impl Ui for WorkerUi {
    fn ask(&self, msg: &str, secret: bool) -> Result<String> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(AppEvent::Prompt { name: self.name.clone(), msg: msg.to_string(), secret, reply })
            .map_err(|_| anyhow!("UI closed"))?;
        match rx.recv() {
            Ok(Some(v)) => Ok(v),
            _ => bail!("cancelled"),
        }
    }
    fn log(&self, line: &str) {
        let _ = self.tx.send(AppEvent::Log(self.name.clone(), line.to_string()));
    }
    fn state(&self, state: &str) {
        let _ = self.tx.send(AppEvent::Phase(self.name.clone(), state.to_lowercase()));
    }
}

struct App {
    store: Store,
    vault: Option<Vault>,
    table: TableState,
    selected: Option<String>,
    states: HashMap<String, TunnelState>,
    /// Tunnels with an operation in progress -> what is happening.
    phases: HashMap<String, String>,
    cancel: HashMap<String, UnixStream>,
    logs: HashMap<String, Vec<String>>,
    modals: VecDeque<Modal>,
    status: (String, Color, Instant),
    shared: Arc<Mutex<Shared>>,
    tx: Sender<AppEvent>,
    quit: bool,
}

pub fn run() -> Result<()> {
    let store = Store::load()?;
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(Mutex::new(Shared::default()));
    let mut app = App {
        store,
        vault: None,
        table: TableState::default(),
        selected: None,
        states: HashMap::new(),
        phases: HashMap::new(),
        cancel: HashMap::new(),
        logs: HashMap::new(),
        modals: VecDeque::new(),
        status: (String::new(), Color::Reset, Instant::now()),
        shared: shared.clone(),
        tx: tx.clone(),
        quit: false,
    };
    app.selected = app.names().into_iter().next();
    app.sync_shared();
    spawn_refresher(tx, shared);

    let mut terminal = ratatui::init();
    let res = app.event_loop(&mut terminal, rx);
    ratatui::restore();
    res
}

fn spawn_refresher(tx: Sender<AppEvent>, shared: Arc<Mutex<Shared>>) {
    thread::spawn(move || {
        loop {
            let (names, busy, selected) = {
                let s = shared.lock().unwrap();
                (s.names.clone(), s.busy.clone(), s.selected.clone())
            };
            let mut candidates: HashSet<String> = names.into_iter().collect();
            candidates.extend(openvpn::socket_names().unwrap_or_default());
            let mut states = HashMap::new();
            for n in candidates {
                if busy.contains(&n) {
                    continue;
                }
                if let Ok(Some(st)) = openvpn::state(&n) {
                    states.insert(n, st);
                }
            }
            let running_sel = selected.filter(|s| states.contains_key(s) && !busy.contains(s));
            if tx.send(AppEvent::States(states)).is_err() {
                return;
            }
            if let Some(sel) = running_sel {
                if let Ok(Some(lines)) = openvpn::logs(&sel) {
                    let _ = tx.send(AppEvent::Logs(sel, lines));
                }
            }
            thread::sleep(REFRESH);
        }
    });
}

fn expand_tilde(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(p),
    }
}

impl App {
    // ---------------------------------------------------------------- helpers

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.store.profiles.keys().cloned().collect();
        for n in self.states.keys().chain(self.phases.keys()) {
            if !names.contains(n) {
                names.push(n.clone());
            }
        }
        names.sort();
        names
    }

    fn sync_shared(&self) {
        let mut s = self.shared.lock().unwrap();
        s.names = self.store.profiles.keys().cloned().collect();
        s.busy = self.phases.keys().cloned().collect();
        s.selected = self.selected.clone();
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.status = (msg.into(), Color::Green, Instant::now());
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.status = (msg.into(), Color::Red, Instant::now());
    }

    fn set_phase(&mut self, name: &str, phase: &str) {
        self.phases.insert(name.to_string(), phase.to_string());
        self.sync_shared();
    }

    fn clear_phase(&mut self, name: &str) {
        self.phases.remove(name);
        self.sync_shared();
    }

    fn push_log(&mut self, name: &str, line: String) {
        let log = self.logs.entry(name.to_string()).or_default();
        log.push(line);
        if log.len() > MAX_LOG_LINES {
            log.drain(..log.len() - MAX_LOG_LINES);
        }
    }

    fn reload_store(&mut self) -> Result<()> {
        self.store = Store::load()?;
        self.sync_shared();
        Ok(())
    }

    fn input(title: impl Into<String>, value: impl Into<String>, secret: bool, purpose: Purpose) -> Modal {
        Modal::Input { title: title.into(), value: value.into(), secret, purpose }
    }

    fn is_running(&self, name: &str) -> bool {
        self.states.contains_key(name)
    }

    // ---------------------------------------------------------------- main loop

    fn event_loop(&mut self, term: &mut DefaultTerminal, rx: Receiver<AppEvent>) -> Result<()> {
        while !self.quit {
            term.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        if let Err(e) = self.on_key(k) {
                            self.error(format!("{e:#}"));
                        }
                    }
                }
            }
            while let Ok(ev) = rx.try_recv() {
                self.on_event(ev);
            }
        }
        // Abort connection attempts still in progress; established tunnels keep running.
        for (_, mut s) in self.cancel.drain() {
            let _ = s.write_all(b"signal SIGTERM\n");
        }
        Ok(())
    }

    fn on_event(&mut self, ev: AppEvent) {
        match ev {
            AppEvent::Prompt { name, msg, secret, reply } => {
                self.modals.push_back(Self::input(msg, "", secret, Purpose::Worker(name, reply)));
            }
            AppEvent::Log(name, line) => self.push_log(&name, line),
            AppEvent::Phase(name, phase) => {
                if self.phases.contains_key(&name) {
                    self.set_phase(&name, &phase);
                }
            }
            AppEvent::Started(name, w) => {
                self.cancel.insert(name, w);
            }
            AppEvent::Connected(name, res) => {
                self.cancel.remove(&name);
                self.clear_phase(&name);
                match res {
                    Ok(Connected { ip, typed }) => {
                        self.states.insert(
                            name.clone(),
                            TunnelState { state: "CONNECTED".into(), local_ip: ip.clone(), remote: String::new() },
                        );
                        self.info(format!("{name}: connected {ip}"));
                        let never = self.store.profiles.get(&name).is_none_or(|p| p.never_save);
                        if let (Some(cred), false) = (typed, never) {
                            self.modals.push_back(Modal::Confirm {
                                text: format!("Save the entered secret(s) for '{name}' in the encrypted vault?"),
                                purpose: ConfirmPurpose::SaveTyped(name, cred),
                            });
                        }
                    }
                    Err(e) => {
                        self.states.remove(&name);
                        self.push_log(&name, format!("ERROR: {e}"));
                        self.error(format!("{name}: {e}"));
                    }
                }
            }
            AppEvent::Stopped(name, res) => {
                self.clear_phase(&name);
                self.states.remove(&name);
                match res {
                    Ok(true) => self.info(format!("{name}: disconnected")),
                    Ok(false) => self.info(format!("{name}: was not running")),
                    Err(e) => self.error(format!("{name}: {e}")),
                }
            }
            AppEvent::States(states) => {
                // Busy tunnels are skipped by the refresher; keep what we know about them.
                let mut new = states;
                for n in self.phases.keys() {
                    if let Some(s) = self.states.get(n) {
                        new.entry(n.clone()).or_insert_with(|| s.clone());
                    }
                }
                self.states = new;
            }
            AppEvent::Logs(name, lines) => {
                if !self.phases.contains_key(&name) {
                    self.logs.insert(name, lines);
                }
            }
        }
    }

    // ---------------------------------------------------------------- keys

    fn on_key(&mut self, k: KeyEvent) -> Result<()> {
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return Ok(());
        }
        if !self.modals.is_empty() {
            return self.on_modal_key(k);
        }
        let names = self.names();
        let idx = self.selected.as_ref().and_then(|s| names.iter().position(|n| n == s));
        match k.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.phases.is_empty() {
                    self.quit = true;
                } else {
                    self.modals.push_back(Modal::Confirm {
                        text: "Connections in progress will be aborted. Quit?".into(),
                        purpose: ConfirmPurpose::Quit,
                    });
                }
            }
            KeyCode::Down | KeyCode::Char('j') if !names.is_empty() => {
                let i = idx.map_or(0, |i| (i + 1).min(names.len() - 1));
                self.selected = Some(names[i].clone());
                self.sync_shared();
            }
            KeyCode::Up | KeyCode::Char('k') if !names.is_empty() => {
                let i = idx.map_or(0, |i| i.saturating_sub(1));
                self.selected = Some(names[i].clone());
                self.sync_shared();
            }
            KeyCode::Char('i') => {
                self.modals.push_back(Self::input("Import .ovpn file (path)", "", false, Purpose::ImportPath));
            }
            KeyCode::Char('r') => {
                self.reload_store()?;
                self.info("reloaded");
            }
            KeyCode::Char('X') => {
                let running: Vec<String> =
                    self.states.keys().filter(|n| !self.phases.contains_key(*n)).cloned().collect();
                for n in running {
                    self.disconnect(&n);
                }
            }
            _ => {
                let Some(name) = self.selected.clone() else { return Ok(()) };
                match k.code {
                    KeyCode::Enter | KeyCode::Char('c') => self.connect(&name)?,
                    KeyCode::Char('x') => self.disconnect(&name),
                    KeyCode::Char('e') => {
                        self.store.get(&name)?;
                        self.start_secrets_flow(name, false);
                    }
                    KeyCode::Char('f') => self.forget(&name)?,
                    KeyCode::Char('o') => {
                        let p = self.store.profiles.get_mut(&name).context("unknown profile")?;
                        p.otp = !p.otp;
                        let on = p.otp;
                        self.store.save()?;
                        self.info(format!("{name}: OTP prompt {}", if on { "on" } else { "off" }));
                    }
                    KeyCode::Char('d') => {
                        if self.is_running(&name) || self.phases.contains_key(&name) {
                            bail!("{name} is running, disconnect it first");
                        }
                        self.store.get(&name)?;
                        self.modals.push_back(Modal::Confirm {
                            text: format!("Delete profile '{name}' and its saved credentials?"),
                            purpose: ConfirmPurpose::Delete(name),
                        });
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn on_modal_key(&mut self, k: KeyEvent) -> Result<()> {
        match self.modals.front_mut() {
            Some(Modal::Confirm { .. }) => {
                let yes = matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter);
                let no = matches!(k.code, KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc);
                if !(yes || no) {
                    return Ok(());
                }
                let Some(Modal::Confirm { purpose, .. }) = self.modals.pop_front() else { unreachable!() };
                match purpose {
                    ConfirmPurpose::Quit if yes => self.quit = true,
                    ConfirmPurpose::Delete(name) if yes => self.delete(&name)?,
                    ConfirmPurpose::SaveTyped(name, cred) => {
                        if yes {
                            self.with_vault(After::SaveCreds(name, cred))?;
                        } else {
                            if let Some(p) = self.store.profiles.get_mut(&name) {
                                p.never_save = true;
                                self.store.save()?;
                            }
                            self.info(format!("{name}: not saved, won't ask again (press e to save later)"));
                        }
                    }
                    ConfirmPurpose::OtpAppended(name, username) => {
                        if let Some(p) = self.store.profiles.get_mut(&name) {
                            p.otp = yes;
                            self.store.save()?;
                        }
                        self.push_password(name, username);
                    }
                    _ => {}
                }
            }
            Some(Modal::Input { value, .. }) => match k.code {
                KeyCode::Esc => {
                    // Dropping the modal drops a worker's reply sender, which cancels it.
                    self.modals.pop_front();
                }
                KeyCode::Enter => {
                    let Some(Modal::Input { value, purpose, .. }) = self.modals.pop_front() else { unreachable!() };
                    self.submit(purpose, value)?;
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => value.clear(),
                KeyCode::Char(c) => value.push(c),
                _ => {}
            },
            None => {}
        }
        Ok(())
    }

    fn submit(&mut self, purpose: Purpose, value: String) -> Result<()> {
        match purpose {
            Purpose::Worker(_, reply) => {
                let _ = reply.send(Some(value));
            }
            Purpose::Master(after) => {
                let value = Zeroizing::new(value);
                match Vault::unlock(&value)? {
                    Some(v) => {
                        self.vault = Some(v);
                        self.do_after(after)?;
                    }
                    None => {
                        self.error("wrong master password");
                        self.modals.push_front(Self::input("Master password", "", true, Purpose::Master(after)));
                    }
                }
            }
            Purpose::NewMaster(after) => {
                if value.is_empty() {
                    self.error("master password must not be empty");
                    self.modals.push_front(Self::input("New master password", "", true, Purpose::NewMaster(after)));
                } else {
                    self.modals.push_front(Self::input(
                        "Repeat master password",
                        "",
                        true,
                        Purpose::RepeatMaster(after, Zeroizing::new(value)),
                    ));
                }
            }
            Purpose::RepeatMaster(after, first) => {
                let value = Zeroizing::new(value);
                if *value == *first {
                    self.vault = Some(Vault::create(&value)?);
                    self.do_after(after)?;
                } else {
                    self.error("passwords do not match");
                    self.modals.push_front(Self::input("New master password", "", true, Purpose::NewMaster(after)));
                }
            }
            Purpose::ImportPath => {
                let path = expand_tilde(value.trim());
                if !path.is_file() {
                    bail!("not a file: {}", path.display());
                }
                let default = profiles::default_name(&path);
                self.modals.push_front(Self::input("Profile name", default, false, Purpose::ImportName(path)));
            }
            Purpose::ImportName(path) => {
                let (name, info) = profiles::import(&path, Some(value.trim().to_string()), false)?;
                self.reload_store()?;
                self.selected = Some(name.clone());
                self.sync_shared();
                for w in &info.warnings {
                    self.push_log(&name, format!("warning: {w}"));
                }
                self.info(format!("imported '{name}'"));
                if self.store.get(&name)?.needs_secrets() {
                    self.start_secrets_flow(name, true);
                }
            }
            Purpose::CredUser(name) => {
                let p = self.store.get(&name)?;
                let (key, sc) = (p.key_encrypted, p.static_challenge);
                if !value.is_empty() {
                    if sc {
                        // OTP comes through static-challenge, the password is fully static.
                        self.push_password(name, value);
                    } else {
                        self.modals.push_front(Modal::Confirm {
                            text: format!("[{name}] Does the password end with an OTP code (password+OTP)?"),
                            purpose: ConfirmPurpose::OtpAppended(name, value),
                        });
                    }
                } else if key {
                    self.push_key_pass(name, None);
                } else {
                    self.info(format!("{name}: nothing saved, will be asked on connect"));
                }
            }
            Purpose::CredPass(name, username) => {
                if self.store.profiles.get(&name).is_some_and(|p| p.key_encrypted) {
                    self.push_key_pass(name, Some((username, value)));
                } else {
                    let cred = Credential { username, password: value, key_pass: None };
                    self.with_vault(After::SaveCreds(name, cred))?;
                }
            }
            Purpose::KeyPass(name, auth) => {
                let (username, password) = auth.unwrap_or_default();
                let key_pass = (!value.is_empty()).then_some(value);
                let cred = Credential { username, password, key_pass };
                if cred.is_empty() {
                    self.info(format!("{name}: nothing saved, will be asked on connect"));
                } else {
                    self.with_vault(After::SaveCreds(name, cred))?;
                }
            }
        }
        Ok(())
    }

    /// Asks for the secrets a profile needs (username/password and/or key passphrase) and saves them.
    fn start_secrets_flow(&mut self, name: String, front: bool) {
        let Some(p) = self.store.profiles.get(&name) else { return };
        let modal = if p.auth || !p.key_encrypted {
            Self::input(
                format!("[{name}] Username (empty = ask on every connect)"),
                "",
                false,
                Purpose::CredUser(name),
            )
        } else {
            Self::input(
                format!("[{name}] Private key passphrase (empty = ask on connect)"),
                "",
                true,
                Purpose::KeyPass(name, None),
            )
        };
        if front { self.modals.push_front(modal) } else { self.modals.push_back(modal) }
    }

    fn push_password(&mut self, name: String, username: String) {
        let appended = self.store.profiles.get(&name).is_some_and(|p| p.otp_appended());
        let title = if appended {
            format!("[{name}] Password: only the static part, OTP is asked on connect")
        } else {
            format!("[{name}] Password")
        };
        self.modals.push_front(Self::input(title, "", true, Purpose::CredPass(name, username)));
    }

    fn push_key_pass(&mut self, name: String, auth: Option<(String, String)>) {
        self.modals.push_front(Self::input(
            format!("[{name}] Private key passphrase (empty = ask on connect)"),
            "",
            true,
            Purpose::KeyPass(name, auth),
        ));
    }

    // ---------------------------------------------------------------- vault

    /// Runs `after` with the vault unlocked, asking for the master password first if needed.
    fn with_vault(&mut self, after: After) -> Result<()> {
        if self.vault.is_some() {
            return self.do_after(after);
        }
        if Vault::exists()? {
            self.modals.push_front(Self::input("Master password", "", true, Purpose::Master(after)));
        } else if matches!(after, After::SaveCreds(..)) {
            self.modals.push_front(Self::input(
                "New master password (protects saved VPN passwords)",
                "",
                true,
                Purpose::NewMaster(after),
            ));
        } else {
            bail!("password vault does not exist");
        }
        Ok(())
    }

    fn do_after(&mut self, after: After) -> Result<()> {
        let vault = self.vault.as_mut().context("vault is locked")?;
        match after {
            After::Connect(name) => {
                // Anything missing from the vault is asked during the connection.
                let creds = vault.get(&name).cloned();
                self.spawn_connect(name, creds);
            }
            After::SaveCreds(name, cred) => {
                let has_auth = cred.has_auth();
                vault.set(&name, cred);
                vault.save()?;
                let p = self.store.profiles.get_mut(&name).context("unknown profile")?;
                if has_auth {
                    p.auth = true;
                }
                p.saved = true;
                p.never_save = false;
                self.store.save()?;
                self.info(format!("{name}: secrets saved (encrypted)"));
            }
            After::Forget(name) => {
                vault.remove(&name);
                vault.save()?;
                if let Some(p) = self.store.profiles.get_mut(&name) {
                    p.saved = false;
                }
                self.store.save()?;
                self.info(format!("{name}: saved credentials deleted"));
            }
            After::Delete(name) => {
                vault.remove(&name);
                vault.save()?;
                self.finish_delete(&name)?;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- actions

    fn connect(&mut self, name: &str) -> Result<()> {
        if self.phases.contains_key(name) || self.is_running(name) {
            self.info(format!("{name}: already running"));
            return Ok(());
        }
        let p = self.store.get(name)?.clone();
        if p.saved {
            self.with_vault(After::Connect(name.to_string()))
        } else {
            self.spawn_connect(name.to_string(), None);
            Ok(())
        }
    }

    fn spawn_connect(&mut self, name: String, creds: Option<Credential>) {
        let Some(profile) = self.store.profiles.get(&name).cloned() else { return };
        self.set_phase(&name, "starting");
        self.logs.insert(name.clone(), Vec::new());
        self.info(format!("{name}: connecting..."));
        let tx = self.tx.clone();
        thread::spawn(move || {
            let ui = WorkerUi { name: name.clone(), tx: tx.clone() };
            let res = openvpn::connect(&name, &profile, creds, &ui, false, |w| {
                let _ = tx.send(AppEvent::Started(name.clone(), w));
            });
            let _ = tx.send(AppEvent::Connected(name, res.map_err(|e| format!("{e:#}"))));
        });
    }

    fn disconnect(&mut self, name: &str) {
        if self.phases.get(name).is_some_and(|p| p != "disconnecting") {
            // Connection in progress: drop its pending prompts and tell openvpn to quit.
            self.modals.retain(|m| !matches!(m, Modal::Input { purpose: Purpose::Worker(n, _), .. } if n == name));
            if let Some(mut s) = self.cancel.remove(name) {
                let _ = s.write_all(b"signal SIGTERM\n");
            }
            self.info(format!("{name}: cancelling..."));
            return;
        }
        if !self.is_running(name) {
            self.info(format!("{name}: not running"));
            return;
        }
        self.set_phase(name, "disconnecting");
        let tx = self.tx.clone();
        let name = name.to_string();
        thread::spawn(move || {
            let res = openvpn::stop(&name).map_err(|e| format!("{e:#}"));
            let _ = tx.send(AppEvent::Stopped(name, res));
        });
    }

    fn forget(&mut self, name: &str) -> Result<()> {
        let p = self.store.get(name)?;
        if !p.saved {
            self.info(format!("{name}: no saved credentials"));
            return Ok(());
        }
        if !Vault::exists()? {
            self.store.profiles.get_mut(name).unwrap().saved = false;
            return self.store.save();
        }
        self.with_vault(After::Forget(name.to_string()))
    }

    fn delete(&mut self, name: &str) -> Result<()> {
        let p = self.store.get(name)?;
        if p.saved && Vault::exists()? {
            self.with_vault(After::Delete(name.to_string()))
        } else {
            self.finish_delete(name)
        }
    }

    fn finish_delete(&mut self, name: &str) -> Result<()> {
        profiles::remove(name)?;
        self.reload_store()?;
        self.logs.remove(name);
        let names = self.names();
        self.selected = names.into_iter().next();
        self.sync_shared();
        self.info(format!("deleted '{name}'"));
        Ok(())
    }

    // ---------------------------------------------------------------- drawing

    fn draw(&mut self, f: &mut Frame) {
        let names = self.names();
        let table_h = (names.len() as u16 + 3).clamp(5, 16);
        let [top, log_area, help_area, status_area] = Layout::vertical([
            Constraint::Length(table_h),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(f.area());

        // Profiles table
        let header = Row::new(["NAME", "STATE", "VPN IP", "SERVER", "OTP", "SECRETS"])
            .style(Style::new().bold().fg(Color::Cyan));
        let rows: Vec<Row> = names
            .iter()
            .map(|n| {
                let (state, style) = if let Some(ph) = self.phases.get(n) {
                    (format!("{ph}…"), Style::new().fg(Color::Yellow))
                } else if let Some(s) = self.states.get(n) {
                    let style = if s.state == "CONNECTED" {
                        Style::new().fg(Color::Green).bold()
                    } else {
                        Style::new().fg(Color::Yellow)
                    };
                    (s.state.to_lowercase(), style)
                } else {
                    ("down".to_string(), Style::new().fg(Color::DarkGray))
                };
                let st = self.states.get(n);
                let (otp, creds) = match self.store.profiles.get(n) {
                    Some(p) => (if p.otp { "yes" } else { "no" }, p.describe_secrets()),
                    None => ("-", "(removed)"),
                };
                Row::new(vec![
                    Cell::from(n.clone()),
                    Cell::from(state).style(style),
                    Cell::from(st.map(|s| s.local_ip.clone()).unwrap_or_default()),
                    Cell::from(st.map(|s| s.remote.clone()).unwrap_or_default()),
                    Cell::from(otp),
                    Cell::from(creds),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(16),
                Constraint::Length(16),
                Constraint::Length(16),
                Constraint::Length(16),
                Constraint::Length(4),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ")
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" warren ".bold())
                .title_bottom(Line::from(format!(" {} connected ", self.states.len())).right_aligned()),
        );
        let idx = self.selected.as_ref().and_then(|s| names.iter().position(|n| n == s));
        self.table.select(idx);
        if names.is_empty() {
            let p = Paragraph::new("No profiles yet. Press i to import an .ovpn file.")
                .block(Block::bordered().border_type(BorderType::Rounded).title(" warren ".bold()));
            f.render_widget(p, top);
        } else {
            f.render_stateful_widget(table, top, &mut self.table);
        }

        // Log of the selected profile
        let title = match &self.selected {
            Some(n) => format!(" log: {n} "),
            None => " log ".to_string(),
        };
        let inner_h = log_area.height.saturating_sub(2) as usize;
        let lines: Vec<Line> = self
            .selected
            .as_ref()
            .and_then(|n| self.logs.get(n))
            .map(|l| {
                l.iter()
                    .skip(l.len().saturating_sub(inner_h))
                    .map(|s| {
                        let style = if s.starts_with("ERROR") || s.contains("AUTH_FAILED") {
                            Style::new().fg(Color::Red)
                        } else if s.starts_with("warning") {
                            Style::new().fg(Color::Yellow)
                        } else {
                            Style::new()
                        };
                        Line::styled(s.clone(), style)
                    })
                    .collect()
            })
            .unwrap_or_default();
        f.render_widget(
            Paragraph::new(lines).block(Block::bordered().border_type(BorderType::Rounded).title(title)),
            log_area,
        );

        // Help + status
        let groups: [&[(&str, &str)]; 3] = [
            &[("⏎", "connect"), ("x", "disconnect"), ("X", "all")],
            &[("i", "import"), ("e", "secrets"), ("f", "forget"), ("o", "otp"), ("d", "delete")],
            &[("q", "quit")],
        ];
        let key_style = Style::new().fg(Color::Cyan);
        let desc_style = Style::new().fg(Color::Gray);
        let sep_style = Style::new().fg(Color::DarkGray);
        let mut spans = vec![Span::raw(" ")];
        for (gi, group) in groups.iter().enumerate() {
            if gi > 0 {
                spans.push(Span::styled("  │  ", sep_style));
            }
            for (ki, (k, d)) in group.iter().enumerate() {
                if ki > 0 {
                    spans.push(Span::styled(" · ", sep_style));
                }
                spans.push(Span::styled(*k, key_style));
                spans.push(Span::styled(format!(" {d}"), desc_style));
            }
        }
        f.render_widget(Paragraph::new(Line::from(spans)), help_area);
        let (msg, color, at) = &self.status;
        if !msg.is_empty() && at.elapsed() < Duration::from_secs(10) {
            let icon = if *color == Color::Red { "✗" } else { "✓" };
            let line = Line::from(vec![
                Span::raw(" "),
                Span::styled(icon, Style::new().fg(*color)),
                Span::raw(" "),
                Span::styled(msg.as_str(), Style::new().fg(*color)),
            ]);
            f.render_widget(Paragraph::new(line), status_area);
        }

        // Modal
        let queued = self.modals.len();
        if let Some(m) = self.modals.front() {
            draw_modal(f, m, queued);
        }
    }
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn draw_modal(f: &mut Frame, m: &Modal, queued: usize) {
    let height = if matches!(m, Modal::Confirm { .. }) { 4 } else { 3 };
    let area = centered(f.area(), 80, height);
    f.render_widget(Clear, area);
    let more = if queued > 1 { format!(" (+{} more) ", queued - 1) } else { String::new() };
    match m {
        Modal::Input { title, value, secret, .. } => {
            let shown = if *secret { "•".repeat(value.chars().count()) } else { value.clone() };
            let block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Cyan))
                .title(format!(" {title} ").bold())
                .title_bottom(Line::from(format!(" enter ok · esc cancel{more}")).right_aligned());
            let inner = block.inner(area);
            f.render_widget(Paragraph::new(format!(" {shown}")).block(block), area);
            let x = inner.x + 1 + shown.chars().count() as u16;
            f.set_cursor_position((x.min(inner.right().saturating_sub(1)), inner.y));
        }
        Modal::Confirm { text, .. } => {
            let block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Yellow))
                .title(" confirm ".bold())
                .title_bottom(Line::from(format!(" y yes · n no{more}")).right_aligned());
            f.render_widget(Paragraph::new(format!(" {text}")).wrap(Wrap { trim: false }).block(block), area);
        }
    }
}
