# ufw-guard

> Compiled Rust wrapper located at `/usr/local/sbin/ufw` enforcing audit comment governance before delegating to `/usr/sbin/ufw`.

---

## Installation

### One-Liner (curl)
```bash
curl -fsSL https://raw.githubusercontent.com/jericbas/ufw-guard/main/install.sh | sudo bash
```

### Via Cargo
```bash
cargo install ufw-guard
```

### Native Packages
Download `.deb` or `.rpm` from the [Latest Release](https://github.com/jericbas/ufw-guard/releases/latest):
- **Debian / Ubuntu**: `sudo apt install ./ufw-guard_<version>_amd64.deb`
- **RHEL / Fedora**: `sudo dnf install ./ufw-guard-<version>-1.x86_64.rpm`

### From Source
```bash
cargo build --release
sudo install -m 755 target/release/ufw /usr/local/sbin/ufw
```

> Need to revert to upstream UFW? See [UNINSTALL.md](UNINSTALL.md).

---

## Usage

```bash
# Rule commands require an audit comment:
ufw allow 22/tcp comment "Allow SSH ingress"

# Missing comments trigger an interactive prompt (or deterministically error in CI/CD non-interactive sessions):
ufw allow 80/tcp

# Emergency break-glass bypass:
ufw allow 443/tcp --force-no-comment
UFW_GUARD_BYPASS=1 ufw allow 443/tcp

# Transparent pass-through for non-rule commands:
ufw status verbose
ufw reload
ufw enable
```

---

## Architecture

```
User / Automation Invocation: `ufw allow 22/tcp`
        │
        ▼ (Standard PATH Precedence: /usr/local/sbin before /usr/sbin)
┌────────────────────────────────────────────────────────┐
│ /usr/local/sbin/ufw (ufw-guard compiled Rust wrapper)   │
│  1. Check UFW_GUARD_BYPASS or --force-no-comment       │
│  2. Inspect subcommand (allow, deny, reject, etc.)     │
│  3. Verify non-empty `comment` parameter               │
│  4. Prompt interactively if missing (or exit on non-tty)│
└────────────────────────────────────────────────────────┘
        │
        ▼ (Exec replacement / execvp)
┌────────────────────────────────────────────────────────┐
│ /usr/sbin/ufw (Original Python/C UFW engine)           │
│  - Executes validated rule against iptables / nftables │
└────────────────────────────────────────────────────────┘
```

---

## Software Philosophy and Principles

`ufw-guard` is built upon five foundational engineering principles:

1. **Governance Without Friction**  
   Security policies must assist administrators rather than obstruct them. Missing comments trigger an interactive prompt in terminal sessions, providing immediate remediation without restarting commands. Non-interactive sessions receive deterministic error diagnostics.

2. **Principle of Least Astonishment**  
   Wrapper behavior is transparent. Non-rule commands (`status`, `enable`, `disable`, `reload`, `reset`, `delete`) pass cleanly to upstream UFW without impedance. Process execution preserves standard streams (`stdin`, `stdout`, `stderr`), exit status codes, and terminal TTY controls.

3. **Fail-Safe & Break-Glass Design**  
   Critical infrastructure must prioritize recoverability during emergencies. Administrators can bypass enforcement using `--force-no-comment` or `UFW_GUARD_BYPASS=1`, stripping wrapper-specific arguments before delegating upstream.

4. **Zero Profile Modification**  
   No shell startup files (`~/.bashrc`, `/etc/profile`, aliases) are altered. `ufw-guard` relies on standard Filesystem Hierarchy Standard (FHS) PATH precedence: `/usr/local/sbin/ufw` executes naturally before `/usr/sbin/ufw`.

5. **Open Source Governance & Ecosystem Interoperability**  
   Dual-licensed under MIT or Apache 2.0. Systems software managing core perimeter security should remain open, auditable, and easily adopted across community and enterprise environments without licensing friction.

---

## License

Dual-licensed under either of:
- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
