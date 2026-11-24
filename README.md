# warren

> A warren is a network of connected burrows. This one is a network of VPN tunnels.

**warren** is a small OpenVPN manager for the terminal. You import your `.ovpn` files once.
After that it keeps the passwords encrypted on disk, asks for one-time codes when you connect,
and runs as many tunnels at the same time as you need. Use it from the CLI, from an
interactive TUI, or through a waybar module.

```
╭ warren ─────────────────────────────────────────────────────────────────────────────╮
│  NAME                     STATE        VPN IP          SERVER          OTP  SECRETS │
│▶ office                   connected    10.8.0.14       203.0.113.10    yes  saved   │
│  datacenter-nue1          connected    10.1.122.143    10.1.2.122      no   saved   │
│  customer-x               down                                         no   ask     │
╰──────────────────────────────────────────────────────────────────────── 2 connected ╯
╭ log: office ────────────────────────────────────────────────────────────────────────╮
│ Initialization Sequence Completed                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────╯
 ⏎ connect · x disconnect · X all  │  i import · e secrets · f forget · o otp · d delete  │  q quit
```

## Why

Plenty of jobs mean being on several VPNs at once: the office, a datacenter or two, a customer
network. Each one comes as an `.ovpn` file, and each one wants something a little different:

- a **username and password**,
- a **password with an OTP code appended** (`MyStaticPassword123456`),
- an OTP through OpenVPN's **static** or **dynamic challenge**,
- an **encrypted private key** with its own passphrase.

The usual options handle this poorly:

- **Plain `openvpn --config x.ovpn`** makes you type everything every time, holds your terminal,
  and keeps each tunnel in its own window.
- **`auth-user-pass creds.txt`** removes the typing, but it leaves your password on disk in plain
  text. It also can't work when part of the password is a code that changes every 30 seconds.
- **NetworkManager** and the GUI clients are clumsy with several tunnels at once and with the
  "static password + OTP" pattern. You also have to go through their dialogs instead of a
  terminal.

warren fixes these points:

1. **Secrets are saved once and encrypted.** They go into a vault protected by a master password,
   and never into a plain text file.
2. **Only the changing part is asked for.** If the password is "static part + OTP", warren saves
   the static part and asks only for the 6 digits when you connect.
3. **Tunnels run in parallel.** `warren connect office datacenter customer-x` brings up three
   independent tunnels.
4. **It fits a keyboard-driven desktop.** There is a CLI for scripts, a TUI for daily use, and a
   waybar module that shows the status at a glance.

## Features

- Import `.ovpn` files. Referenced `ca`/`cert`/`key` files are copied along.
- An encrypted vault for usernames, passwords and private key passphrases (Argon2id + XChaCha20-Poly1305).
- OTP support:
  - **static-challenge** (`static-challenge` in the config): detected automatically
  - **dynamic challenge** (CRV1): the server asks, you answer
  - **password + OTP**: the static part is saved and the OTP is appended when you connect
- Several tunnels at once, each one its own `openvpn` daemon.
- Credentials go to openvpn through its management socket, so they are never written to a file.
- A TUI with live state, VPN IP and per-tunnel logs.
- After a connect where you typed secrets, warren offers to save them.
- A waybar custom module (JSON output).
- Nix flake: `nix run`, `nix profile install`, or a NixOS system package, with openvpn included.

## Installation

warren runs on **Linux**. It needs **OpenVPN 2.4+** and **sudo**, because creating a tun
device requires root.

### Option 1: Nix flake (recommended)

The flake package wraps the binary with `openvpn` from nixpkgs, so you don't need openvpn
installed separately.

**Try it without installing:**

```bash
nix run github:lazicnemanja/warren
```

**Install into your user profile:**

```bash
nix profile install github:lazicnemanja/warren
# later, to update:
nix profile upgrade warren
```

**As a NixOS system package (flake-based config):**

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    warren = {
      url = "github:lazicnemanja/warren";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, warren, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        {
          environment.systemPackages = [ warren.packages.x86_64-linux.default ];
        }
      ];
    };
  };
}
```

Then `sudo nixos-rebuild switch --flake .#my-host`. To get a newer version later, run
`nix flake update warren` and rebuild.

**With home-manager:**

```nix
home.packages = [ inputs.warren.packages.${pkgs.stdenv.hostPlatform.system}.default ];
```

**Development shell** (cargo, rustc, clippy, rust-analyzer, openvpn):

```bash
git clone https://github.com/lazicnemanja/warren && cd warren
nix develop
cargo run
```

### Option 2: Cargo (any distro)

Building needs **Rust 1.85 or newer** (edition 2024).

1. Install OpenVPN and a Rust toolchain:

   ```bash
   # Debian / Ubuntu
   sudo apt install openvpn
   # Fedora
   sudo dnf install openvpn
   # Arch
   sudo pacman -S openvpn

   # Rust (if you don't have it)
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Install warren:

   ```bash
   cargo install --git https://github.com/lazicnemanja/warren
   ```

   or from a checkout:

   ```bash
   git clone https://github.com/lazicnemanja/warren && cd warren
   cargo install --path .
   ```

   The binary ends up in `~/.cargo/bin/warren`. Make sure that directory is on your `PATH`.

3. Check that it can find openvpn:

   ```bash
   warren list
   ```

   warren looks for `openvpn` on your `PATH`, then in `/usr/sbin`, `/sbin` and
   `/run/current-system/sw/bin`. If yours is somewhere else, point warren at it:

   ```bash
   export WARREN_OPENVPN=/path/to/openvpn
   ```

### Optional: sudo without a password for openvpn

warren asks for your sudo password when it starts a tunnel (in the TUI through a prompt, in the
CLI through sudo itself). To skip that, allow openvpn without a password:

```
# /etc/sudoers.d/warren   (edit with: sudo visudo -f /etc/sudoers.d/warren)
youruser ALL=(root) NOPASSWD: /usr/sbin/openvpn
```

On NixOS, the flake package runs openvpn from its own store path. With
`inputs.nixpkgs.follows = "nixpkgs"` that is the same `pkgs.openvpn` as your system's:

```nix
security.sudo.extraRules = [{
  users = [ "youruser" ];
  commands = [{ command = "${pkgs.openvpn}/bin/openvpn"; options = [ "NOPASSWD" ]; }];
}];
```

The rule must name the exact binary warren runs: `echo $WARREN_OPENVPN` inside the wrapper
(`cat $(which warren)` shows it), or `which openvpn` for a cargo install.
Running openvpn as root with a config you choose is equivalent to root access, so only do this
on a machine you trust.

## Quick start

```bash
# 1. Import a profile. warren asks for whatever the config needs:
#    username, whether the password ends with an OTP, password (static part), key passphrase.
#    The first time, it also creates the vault and asks for a new master password.
warren import ~/Downloads/office.ovpn

# 2. Connect. You get the master password prompt, sudo, and the OTP if needed.
warren connect office

# 3. See what's up
warren list

# 4. Or just open the TUI
warren
```

## Usage

### TUI

Run `warren` with no arguments (or `warren tui`).

| Key | Action |
|---|---|
| `↑` `↓` / `k` `j` | select a profile |
| `Enter` / `c` | connect the selected profile |
| `x` | disconnect the selected profile (or cancel a connect in progress) |
| `X` | disconnect all tunnels |
| `i` | import an `.ovpn` file (`~/` paths work) |
| `e` | set or replace saved secrets (username, password, key passphrase) |
| `f` | forget saved secrets (they will be asked on every connect) |
| `o` | toggle the OTP prompt |
| `d` | delete the profile and its saved secrets |
| `r` | reload profiles from disk |
| `q` / `Esc` | quit (tunnels keep running) |

Prompts such as the sudo password, master password, OTP and passphrases appear as modal
dialogs. If several tunnels need input at the same time, the prompts queue up. `Esc` on a
prompt cancels that connection.

Quitting the TUI doesn't disconnect anything. The tunnels are openvpn daemons, and the next
`warren` or `warren list` picks them up again.

### CLI

```
warren                          open the TUI
warren import <file.ovpn>       import a profile
    -n, --name <NAME>           profile name (default: file name)
        --otp                   ask for an OTP on every connect
        --no-save               don't store secrets, ask on every connect
warren list                     profiles + state, VPN IP, server   (aliases: ls, status)
warren connect <NAME>...        connect one or more profiles       (alias: up)
    -v, --verbose               show the openvpn log while connecting
warren disconnect <NAME>...     disconnect                         (alias: down)
    -a, --all                   disconnect every running tunnel
warren edit <NAME>
        --otp true|false        enable/disable the OTP prompt
        --credentials           set/replace saved secrets
        --forget                delete saved secrets
warren remove <NAME>            delete a profile + its secrets     (alias: rm)
warren logs <NAME> [-n 40]      log of a running tunnel
warren passwd                   change the vault master password
warren waybar                   waybar module (see below)
```

Examples:

```bash
warren import customer.ovpn --name customer-x --no-save
warren up office datacenter-nue1          # two tunnels, one master password prompt
warren down --all
warren edit office --otp true
```

### Passwords, OTP and passphrases

warren reads the config to work out what a profile needs:

| Config contains | warren will |
|---|---|
| `auth-user-pass` | ask for username + password (saved in the vault) |
| `static-challenge "..."` | ask for the OTP separately on each connect (password stays static) |
| an encrypted `<key>` / key file | ask for the private key passphrase (saved in the vault) |
| nothing of the above | connect with certificates only |

For the very common **"password = static part + OTP code"** setup, answer *yes* to *"Does the
password end with an OTP code?"* when importing (or later with `warren edit NAME --otp true`).
Save only the static part. On connect, warren asks for the code and sends `static part + code`.

Dynamic challenges (CRV1, where the server replies with a question after the first login) are
always handled: warren shows the challenge text and asks for the response.

If you type a secret during a connect that wasn't saved, warren offers to save it once the
tunnel is up. If you say no, it won't ask again for that profile (`e` in the TUI or
`warren edit --credentials` saves it later).

## Waybar module

`warren waybar` runs continuously and prints a JSON line whenever the state changes:

| State | Text | CSS class |
|---|---|---|
| nothing connected | `󰖂  off` (or hidden with `--hide-when-off`) | `off` |
| one tunnel up | `󰖂  office` | `connected` |
| several tunnels | `󰖂  2 VPNs` | `connected` |
| a tunnel is connecting | `󰖂  office…` | `connecting` |

The tooltip lists every tunnel with its VPN IP.

`~/.config/waybar/config.jsonc`:

```jsonc
"modules-right": ["custom/warren", "network", "battery"],

"custom/warren": {
    "exec": "warren waybar --max-length 20",
    "return-type": "json",
    "restart-interval": 10,
    "escape": false,
    "on-click": "alacritty --class warren --title warren -e warren",
    "on-click-right": "warren disconnect --all"
}
```

Options: `--interval <seconds>` (default 2), `--max-length <chars>` (default 24),
`--hide-when-off`.

`~/.config/waybar/style.css` (Catppuccin Mocha colours, adjust to taste):

```css
#custom-warren            { padding: 0 14px; }
#custom-warren.connected  { color: #a6e3a1; }
#custom-warren.connecting { color: #f9e2af; }
#custom-warren.off        { color: #6c7086; }
```

To open the TUI as a floating window on click, add a window rule for `app-id` / class `warren`.
For [niri](https://github.com/YaLTeR/niri):

```kdl
window-rule {
    match app-id=r#"^warren$"#
    open-floating true
    default-column-width { fixed 1100; }
    default-window-height { fixed 600; }
}
```

Use your own terminal in place of `alacritty` if you have a different one; most accept a
class or app-id flag (`kitty --class warren`, `foot --app-id warren`, …).

## How it works

```
warren ──sudo──▶ openvpn --daemon --management $XDG_RUNTIME_DIR/warren/<name>.sock unix
   │                       --management-query-passwords --management-hold ...
   └──── unix socket ────▶ answers ">PASSWORD:Need 'Auth'" / "Need 'Private Key'"
                           follows ">STATE:" until CONNECTED, then lets go
```

- Every tunnel is its own `openvpn` daemon with its own **management socket**. warren gives
  openvpn the credentials over that socket in reply to its requests, so they never sit in a
  temporary file.
- The socket belongs to your user (`--management-client-user`), which is why `list`,
  `disconnect`, `logs` and the waybar module work **without sudo**.
- Tunnels don't depend on warren after connecting. Quit the TUI, close the terminal: they keep
  running until you disconnect them.

### Files

| Path | Contents |
|---|---|
| `~/.config/warren/profiles.json` | profile metadata (no secrets) |
| `~/.config/warren/profiles/<name>/` | the imported `config.ovpn` + referenced cert/key files |
| `~/.config/warren/vault.json` | encrypted secrets |
| `$XDG_RUNTIME_DIR/warren/` | management sockets and logs of running tunnels |

Everything is created with `0700`/`0600` permissions.

### Security

- **Vault:** the key comes from your master password via **Argon2id** (64 MiB, 3 passes), and
  the content is encrypted with **XChaCha20-Poly1305**, using a fresh random nonce on every save.
  The master password itself is never stored.
- **Secrets in memory** are zeroized when dropped, where practical.
- The TUI keeps the vault unlocked while it runs, and the CLI only for one command.
- warren writes no plain text secrets to disk. Your imported `.ovpn` files are copied as they
  are, so if they contain inline keys, protect `~/.config/warren` the same way you'd protect
  the originals.
- **No recovery:** if you forget the master password, delete `vault.json` and enter the
  secrets again.

## Troubleshooting

**`openvpn binary not found`**: install openvpn, or set `WARREN_OPENVPN=/path/to/openvpn`.
The Nix package sets this for you.

**Two tunnels fight over routes or DNS**: warren starts each tunnel separately, but the configs
can still clash. Two `redirect-gateway` tunnels, or overlapping pushed routes, will interfere.
Fix it in the `.ovpn` files or on the server side (`route-nopull`, explicit `route` lines).

**A tunnel drops and needs a new OTP**: openvpn can reconnect on its own with cached
credentials. Servers that demand a fresh OTP on every connection will fail on reconnect. Run
`warren connect` again.

**Connection fails**: run `warren connect -v NAME` to watch the full openvpn log. Logs of
tunnels that already stopped are owned by root:
`sudo cat $XDG_RUNTIME_DIR/warren/NAME.log`.

**"saved private key passphrase is wrong"**: press `e` in the TUI (or run
`warren edit NAME --credentials`) and enter it again.

## License

[MIT](LICENSE)
