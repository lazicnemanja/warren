use std::io::{self, BufRead, Write};

use anyhow::{Result, bail};
use zeroize::Zeroizing;

pub fn prompt_line(msg: &str) -> Result<String> {
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut s = String::new();
    if io::stdin().lock().read_line(&mut s)? == 0 {
        bail!("stdin closed");
    }
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

pub fn prompt_secret(msg: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(msg)?))
}

pub fn confirm(msg: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let ans = prompt_line(&format!("{msg} {hint} "))?;
    Ok(match ans.trim().to_lowercase().as_str() {
        "" => default,
        "y" | "yes" | "d" | "da" => true,
        _ => false,
    })
}
