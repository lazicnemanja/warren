//! Starting openvpn and talking to it over its management interface (unix socket).
//!
//! Credentials are handed over the socket in response to `>PASSWORD:Need 'Auth'`
//! requests, so they never touch the disk in plain text.

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use zeroize::Zeroizing;

use crate::paths;
use crate::profiles::Profile;
use crate::vault::Credential;

/// How the connection logic talks to the user (terminal prompts in the CLI, modals in the TUI).
pub trait Ui {
    /// Ask the user for a value. `msg` has no trailing colon.
    fn ask(&self, msg: &str, secret: bool) -> Result<String>;
    /// A line from the openvpn log.
    fn log(&self, _line: &str) {}
    /// openvpn state change (CONNECTING, AUTH, GET_CONFIG, ...).
    fn state(&self, _state: &str) {}
}

pub struct Mgmt {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Mgmt {
    pub fn connect(path: &Path) -> io::Result<Self> {
        let s = UnixStream::connect(path)?;
        let writer = s.try_clone()?;
        Ok(Self { reader: BufReader::new(s), writer })
    }

    pub fn set_timeout(&self, d: Duration) -> io::Result<()> {
        self.writer.set_read_timeout(Some(d))
    }

    pub fn send(&mut self, cmd: &str) -> Result<()> {
        self.writer.write_all(cmd.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn read_line(&mut self) -> Result<Option<String>> {
        let mut s = String::new();
        match self.reader.read_line(&mut s) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(s.trim_end_matches(['\r', '\n']).to_string())),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                bail!("timed out waiting for openvpn")
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Sends a command whose reply is a block of lines terminated by `END`.
    pub fn command_multiline(&mut self, cmd: &str) -> Result<Vec<String>> {
        self.send(cmd)?;
        let mut out = Vec::new();
        while let Some(line) = self.read_line()? {
            if line.starts_with('>') {
                continue; // asynchronous notification
            }
            if line == "END" {
                return Ok(out);
            }
            if line.starts_with("ERROR:") {
                bail!("openvpn: {line}");
            }
            out.push(line);
        }
        bail!("connection closed")
    }
}

/// Quote a value for the management protocol.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn find_openvpn() -> Result<PathBuf> {
    if let Some(p) = env::var_os("WARREN_OPENVPN") {
        return Ok(PathBuf::from(p));
    }
    let path = env::var_os("PATH").unwrap_or_default();
    let candidates = env::split_paths(&path).map(|d| d.join("openvpn")).chain(
        ["/usr/sbin/openvpn", "/sbin/openvpn", "/run/current-system/sw/bin/openvpn"]
            .into_iter()
            .map(PathBuf::from),
    );
    for c in candidates {
        if c.is_file() {
            return Ok(c);
        }
    }
    bail!("openvpn binary not found (install it or set WARREN_OPENVPN=/path/to/openvpn)")
}

/// Returns a management connection if the tunnel `name` is running.
/// Removes stale sockets left behind by a dead openvpn.
pub fn connect_running(name: &str) -> Result<Option<Mgmt>> {
    let sock = paths::socket_path(name)?;
    if !sock.exists() {
        return Ok(None);
    }
    match Mgmt::connect(&sock) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            let _ = fs::remove_file(&sock);
            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("cannot connect to {}", sock.display())),
    }
}

/// Names that have a management socket file (may be stale).
pub fn socket_names() -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(paths::runtime_dir()?)? {
        let p = entry?.path();
        if p.extension().is_some_and(|e| e == "sock") {
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Names of all tunnels that are actually running.
pub fn running_names() -> Result<Vec<String>> {
    let mut names = Vec::new();
    for n in socket_names()? {
        if connect_running(&n)?.is_some() {
            names.push(n);
        }
    }
    Ok(names)
}

static SUDO_LOCK: Mutex<()> = Mutex::new(());

/// Makes sure `sudo -n` will work, asking for the sudo password through `ui` if needed.
fn ensure_sudo(ui: &dyn Ui) -> Result<()> {
    if paths::is_root() {
        return Ok(());
    }
    // Serialize so parallel connects don't all ask for the sudo password.
    let _guard = SUDO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let quiet = |c: &mut Command| {
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    };
    let mut check = Command::new("sudo");
    check.args(["-n", "true"]);
    quiet(&mut check);
    if check.status().is_ok_and(|s| s.success()) {
        return Ok(());
    }
    for _ in 0..3 {
        let pw = Zeroizing::new(ui.ask("sudo password", true)?);
        let mut child = Command::new("sudo")
            .args(["-S", "-p", "", "-v"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("cannot run sudo")?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(pw.as_bytes());
            let _ = stdin.write_all(b"\n");
        }
        if child.wait()?.success() {
            return Ok(());
        }
    }
    bail!("sudo authentication failed")
}

/// Launches openvpn (via sudo) as a daemon in management-hold mode and connects to it.
///
/// `interactive`: sudo may prompt on the terminal. Otherwise `sudo -n` is used and output is
/// captured, so nothing is written to the terminal (needed for the TUI).
pub fn start(name: &str, with_auth: bool, interactive: bool) -> Result<Mgmt> {
    let openvpn = find_openvpn()?;
    let dir = paths::profile_dir(name)?;
    let sock = paths::socket_path(name)?;
    let log = paths::log_path(name)?;
    let err_path = paths::runtime_dir()?.join(format!("{name}.err"));
    let _ = fs::remove_file(&sock);

    let mut cmd = if paths::is_root() {
        Command::new(&openvpn)
    } else {
        let mut c = Command::new("sudo");
        if !interactive {
            c.arg("-n");
        }
        c.arg(&openvpn);
        c
    };
    cmd.arg("--cd").arg(&dir);
    cmd.arg("--config").arg(dir.join("config.ovpn"));
    cmd.arg("--daemon").arg(format!("warren-{name}"));
    cmd.arg("--log").arg(&log);
    cmd.arg("--management").arg(&sock).arg("unix");
    cmd.arg("--management-client-user").arg(paths::current_user()?);
    cmd.args(["--management-query-passwords", "--management-hold", "--auth-retry", "interact"]);
    if with_auth {
        // Overrides any `auth-user-pass <file>` in the config: ask via management instead.
        cmd.arg("--auth-user-pass");
    }
    if !interactive {
        let errf = fs::File::create(&err_path)?;
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(errf);
    }

    let status = cmd.status().context("failed to run openvpn")?;
    if !status.success() {
        let detail = fs::read_to_string(&err_path).unwrap_or_default();
        let detail = detail.trim();
        if detail.is_empty() {
            bail!("openvpn failed to start ({status}); log: sudo cat {}", log.display());
        }
        bail!("openvpn failed to start: {detail}");
    }

    for _ in 0..100 {
        if let Ok(m) = Mgmt::connect(&sock) {
            return Ok(m);
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("openvpn did not open its management socket; check `sudo cat {}`", log.display())
}

fn prompt_otp(ui: &dyn Ui, text: &str, echo: bool) -> Result<String> {
    ui.ask(text.trim().trim_end_matches(':'), !echo)
}

/// Asks for username + password and stores them into `cred`.
/// `static_part`: the OTP is appended at connect, so only the static password is asked.
pub fn prompt_auth(name: &str, ui: &dyn Ui, cred: &mut Credential, static_part: bool) -> Result<()> {
    cred.username = ui.ask(&format!("[{name}] Username"), false)?;
    let label = if static_part { "Password (static part, without OTP)" } else { "Password" };
    cred.password = ui.ask(&format!("[{name}] {label}"), true)?;
    Ok(())
}

pub fn prompt_key_pass(name: &str, ui: &dyn Ui) -> Result<String> {
    ui.ask(&format!("[{name}] Private key passphrase"), true)
}

/// Asks for every secret `profile` needs (for import / edit).
pub fn prompt_secrets(name: &str, profile: &Profile, ui: &dyn Ui) -> Result<Credential> {
    let mut c = Credential::default();
    if profile.auth || !profile.key_encrypted {
        prompt_auth(name, ui, &mut c, profile.otp_appended())?;
    }
    if profile.key_encrypted {
        c.key_pass = Some(prompt_key_pass(name, ui)?);
    }
    Ok(c)
}

pub struct Connected {
    pub ip: String,
    /// Saved secrets merged with what the user typed in, if anything was typed.
    pub typed: Option<Credential>,
}

/// Starts the tunnel and authenticates.
///
/// `saved` are the secrets from the vault; anything missing is asked through `ui`.
/// `on_started` receives a write handle to the management socket as soon as openvpn is up;
/// writing `signal SIGTERM\n` to it aborts the connection attempt.
pub fn connect(
    name: &str,
    profile: &Profile,
    saved: Option<Credential>,
    ui: &dyn Ui,
    interactive: bool,
    on_started: impl FnOnce(UnixStream),
) -> Result<Connected> {
    find_openvpn()?;
    if !interactive {
        ensure_sudo(ui)?;
    }
    ui.state("STARTING");
    let mut m = start(name, profile.auth, interactive)?;
    if let Ok(w) = m.writer.try_clone() {
        on_started(w);
    }
    match authenticate(&mut m, name, saved, profile.otp, ui) {
        Ok(c) => Ok(c),
        Err(e) => {
            let _ = m.send("signal SIGTERM");
            Err(e)
        }
    }
}

/// Drives the openvpn session until it is connected, answering credential/OTP requests.
fn authenticate(
    m: &mut Mgmt,
    name: &str,
    saved: Option<Credential>,
    otp: bool,
    ui: &dyn Ui,
) -> Result<Connected> {
    m.set_timeout(Duration::from_secs(180))?;
    m.send("state on")?;
    m.send("log on")?;
    // `hold off` so automatic reconnects later don't wait for a management client.
    m.send("hold off")?;
    m.send("hold release")?;

    // Pending dynamic challenge (CRV1): (state id, username).
    let mut crv1: Option<(String, String)> = None;
    let mut creds = saved.unwrap_or_default();
    let mut typed = false;
    let mut key_from_vault = false;
    let mut key_asked = 0;

    while let Some(line) = m.read_line()? {
        if let Some(rest) = line.strip_prefix(">LOG:") {
            let msg = rest.splitn(3, ',').nth(2).unwrap_or(rest);
            if !is_mgmt_noise(msg) {
                ui.log(msg);
            }
        } else if line.starts_with(">HOLD:") {
            m.send("hold release")?;
        } else if let Some(rest) = line.strip_prefix(">PASSWORD:") {
            if rest.starts_with("Need 'Auth'") {
                if !creds.has_auth() {
                    prompt_auth(name, ui, &mut creds, otp && !rest.contains(" SC:"))?;
                    typed = true;
                }
                let creds = &creds;
                let (user, pass) = if let Some((state, user)) = crv1.take() {
                    let resp = prompt_otp(ui, &format!("[{name}] Challenge response"), true)?;
                    (user, format!("CRV1::{state}::{resp}"))
                } else if let Some((_, sc)) = rest.split_once(" SC:") {
                    // static-challenge: "SC:<flags>,<text>"
                    let (flags, text) = sc.split_once(',').unwrap_or(("0", sc));
                    let echo = flags.parse::<u32>().unwrap_or(0) & 1 == 1;
                    let code = prompt_otp(ui, &format!("[{name}] {text}"), echo)?;
                    let pass = format!("SCRV1:{}:{}", B64.encode(&creds.password), B64.encode(code));
                    (creds.username.clone(), pass)
                } else if otp {
                    let code = prompt_otp(ui, &format!("[{name}] OTP"), true)?;
                    (creds.username.clone(), format!("{}{}", creds.password, code))
                } else {
                    (creds.username.clone(), creds.password.clone())
                };
                let pass = Zeroizing::new(pass);
                m.send(&format!("username \"Auth\" {}", quote(&user)))?;
                m.send(&Zeroizing::new(format!("password \"Auth\" {}", quote(&pass))))?;
            } else if rest.starts_with("Need 'Private Key'") {
                key_asked += 1;
                if key_asked > 3 {
                    bail!("wrong private key passphrase");
                }
                if key_asked > 1 {
                    ui.log("private key passphrase rejected, asking again");
                }
                let pw = match &creds.key_pass {
                    Some(p) if key_asked == 1 => {
                        key_from_vault = !typed;
                        p.clone()
                    }
                    _ => {
                        let p = prompt_key_pass(name, ui)?;
                        creds.key_pass = Some(p.clone());
                        typed = true;
                        p
                    }
                };
                let pw = Zeroizing::new(pw);
                m.send(&Zeroizing::new(format!("password \"Private Key\" {}", quote(&pw))))?;
            } else if rest.starts_with("Verification Failed") && rest.contains("'Private Key'") {
                if key_from_vault {
                    bail!("saved private key passphrase is wrong (update it with `e` / `warren edit --credentials`)");
                }
                bail!("wrong private key passphrase");
            } else if rest.starts_with("Verification Failed") {
                if let Some(idx) = rest.find("CRV1:") {
                    // CRV1:<flags>:<state_id>:<username_b64>:<challenge text>']
                    let body = rest[idx + 5..].trim_end_matches(['\'', ']']);
                    let parts: Vec<&str> = body.splitn(4, ':').collect();
                    if parts.len() == 4 {
                        let user = String::from_utf8(B64.decode(parts[2])?)?;
                        ui.log(&format!("challenge: {}", parts[3]));
                        crv1 = Some((parts[1].to_string(), user));
                        continue;
                    }
                }
                bail!("authentication failed (wrong username/password/OTP?)");
            }
        } else if let Some(rest) = line.strip_prefix(">STATE:") {
            // <time>,<state>,<desc>,<local ip>,<remote ip>,...
            let f: Vec<&str> = rest.split(',').collect();
            let state = f.get(1).copied().unwrap_or("");
            ui.state(state);
            match state {
                "CONNECTED" => {
                    if f.get(2).copied() == Some("ERROR") {
                        ui.log("warning: connected with errors (check routes/scripts)");
                    }
                    return Ok(Connected {
                        ip: f.get(3).copied().unwrap_or("").to_string(),
                        typed: typed.then(|| creds.clone()),
                    });
                }
                "EXITING" => bail!("openvpn exited: {}", f.get(2).copied().unwrap_or("")),
                _ => {}
            }
        } else if let Some(rest) = line.strip_prefix(">FATAL:") {
            bail!("openvpn fatal error: {rest}");
        }
    }
    bail!("openvpn closed the management connection")
}

/// Sends SIGTERM to the tunnel and waits for it to go away.
pub fn stop(name: &str) -> Result<bool> {
    let Some(mut m) = connect_running(name)? else { return Ok(false) };
    m.set_timeout(Duration::from_secs(10))?;
    m.send("signal SIGTERM")?;
    while let Ok(Some(_)) = m.read_line() {}
    let _ = fs::remove_file(paths::socket_path(name)?);
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct TunnelState {
    pub state: String,
    pub local_ip: String,
    pub remote: String,
}

pub fn state(name: &str) -> Result<Option<TunnelState>> {
    let Some(mut m) = connect_running(name)? else { return Ok(None) };
    m.set_timeout(Duration::from_secs(3))?;
    let lines = m.command_multiline("state")?;
    let last = lines.last().map(String::as_str).unwrap_or("");
    let f: Vec<&str> = last.split(',').collect();
    Ok(Some(TunnelState {
        state: f.get(1).copied().unwrap_or("?").to_string(),
        local_ip: f.get(3).copied().unwrap_or("").to_string(),
        remote: f.get(4).copied().unwrap_or("").to_string(),
    }))
}

pub fn logs(name: &str) -> Result<Option<Vec<String>>> {
    let Some(mut m) = connect_running(name)? else { return Ok(None) };
    m.set_timeout(Duration::from_secs(3))?;
    let lines = m.command_multiline("log all")?;
    Ok(Some(
        lines
            .into_iter()
            .map(|l| l.splitn(3, ',').nth(2).map(str::to_string).unwrap_or(l))
            .filter(|l| !is_mgmt_noise(l))
            .collect(),
    ))
}

/// Log lines produced by our own management polling (connect/state/log/disconnect).
fn is_mgmt_noise(line: &str) -> bool {
    line.starts_with("MANAGEMENT:") && !line.contains(">STATE:")
}
