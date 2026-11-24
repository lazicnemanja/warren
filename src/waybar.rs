//! `warren waybar`: a waybar custom module (return-type: json).
//!
//! Runs forever, polling the running tunnels and printing one JSON line whenever the
//! output changes, like waybar expects from a long-running `exec`.

use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use crate::openvpn::{self, TunnelState};

const ICON: &str = "󰖂";

#[derive(Serialize, PartialEq)]
struct Output {
    text: String,
    tooltip: String,
    class: Vec<&'static str>,
    alt: &'static str,
}

pub struct Options {
    pub interval: u64,
    pub hide_when_off: bool,
    pub max_length: usize,
}

pub fn run(opts: &Options) -> Result<()> {
    let mut last: Option<Output> = None;
    let mut stdout = io::stdout().lock();
    loop {
        let out = render(opts);
        if last.as_ref() != Some(&out) {
            // A write error means waybar went away: exit quietly.
            if writeln!(stdout, "{}", serde_json::to_string(&out)?).and_then(|_| stdout.flush()).is_err() {
                return Ok(());
            }
            last = Some(out);
        }
        thread::sleep(Duration::from_secs(opts.interval.max(1)));
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn render(opts: &Options) -> Output {
    // None = tunnel exists but didn't answer (busy, e.g. a connect in progress).
    let mut tunnels: Vec<(String, Option<TunnelState>)> = Vec::new();
    for name in openvpn::socket_names().unwrap_or_default() {
        match openvpn::state(&name) {
            Ok(Some(s)) => tunnels.push((name, Some(s))),
            Ok(None) => {}
            Err(_) => tunnels.push((name, None)),
        }
    }
    build(&tunnels, opts)
}

fn build(tunnels: &[(String, Option<TunnelState>)], opts: &Options) -> Output {
    let is_up = |s: &Option<TunnelState>| s.as_ref().is_some_and(|s| s.state == "CONNECTED");
    let up: Vec<&String> = tunnels.iter().filter(|(_, s)| is_up(s)).map(|(n, _)| n).collect();
    let pending: Vec<&String> = tunnels.iter().filter(|(_, s)| !is_up(s)).map(|(n, _)| n).collect();

    let hint = "<small>click: open warren · right-click: disconnect all</small>";
    if tunnels.is_empty() {
        return Output {
            text: if opts.hide_when_off { String::new() } else { format!("{ICON}  off") },
            tooltip: format!("No VPN connected\n\n{hint}"),
            class: vec!["off"],
            alt: "off",
        };
    }

    let text = match (tunnels.len(), up.first()) {
        (1, Some(n)) => format!("{ICON}  {}", escape(&truncate(n, opts.max_length))),
        (1, None) => format!("{ICON}  {}…", escape(&truncate(pending[0], opts.max_length))),
        (n, _) => format!("{ICON}  {n} VPNs"),
    };

    let mut lines = Vec::new();
    for (name, state) in tunnels {
        let line = match state {
            Some(s) if s.state == "CONNECTED" => {
                format!("<b>{}</b>  {}", escape(name), escape(&s.local_ip))
            }
            Some(s) => format!("<b>{}</b>  {}…", escape(name), escape(&s.state.to_lowercase())),
            None => format!("<b>{}</b>  busy…", escape(name)),
        };
        lines.push(line);
    }
    let (class, alt) = if pending.is_empty() { ("connected", "connected") } else { ("connecting", "connecting") };
    Output { text, tooltip: format!("{}\n\n{hint}", lines.join("\n")), class: vec![class], alt }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(state: &str, ip: &str) -> Option<TunnelState> {
        Some(TunnelState { state: state.into(), local_ip: ip.into(), remote: String::new() })
    }

    const OPTS: Options = Options { interval: 2, hide_when_off: false, max_length: 16 };

    #[test]
    fn off() {
        let o = build(&[], &OPTS);
        assert_eq!(o.text, "󰖂  off");
        assert_eq!(o.class, vec!["off"]);
        let hidden = build(&[], &Options { hide_when_off: true, ..OPTS });
        assert_eq!(hidden.text, "");
    }

    #[test]
    fn one_connected_truncated() {
        let o = build(&[("NemanjaLazic-coloc-nue1".into(), st("CONNECTED", "10.1.122.143"))], &OPTS);
        assert_eq!(o.text, "󰖂  NemanjaLazic-co…");
        assert_eq!(o.class, vec!["connected"]);
        assert!(o.tooltip.contains("<b>NemanjaLazic-coloc-nue1</b>  10.1.122.143"));
    }

    #[test]
    fn connecting_and_multiple() {
        let o = build(&[("a".into(), None)], &OPTS);
        assert_eq!((o.text.as_str(), o.class[0]), ("󰖂  a…", "connecting"));

        let o = build(&[("a".into(), st("CONNECTED", "10.0.0.2")), ("b<x>".into(), st("AUTH", ""))], &OPTS);
        assert_eq!((o.text.as_str(), o.class[0]), ("󰖂  2 VPNs", "connecting"));
        assert!(o.tooltip.contains("<b>b&lt;x&gt;</b>  auth…"));
    }
}
