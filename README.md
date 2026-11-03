# ufw-guard

> Compiled Rust wrapper located at `/usr/local/sbin/ufw` enforcing audit comment governance before delegating to `/usr/sbin/ufw`.

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

5. **Authorship Protection & Open Source Governance**  
   Licensed under GNU General Public License v3.0 (GPLv3). Systems software managing core perimeter security must remain open, auditable, and protected against proprietary relicensing.

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

## Installation

### One-Liner (curl)
```bash
curl -fsSL https://raw.githubusercontent.com/jericbas/ufw-guard/main/install.sh | sudo bash
```

### Native Packages
- **Debian / Ubuntu**: `sudo apt install ./ufw-guard_<version>_amd64.deb`
- **RHEL / Fedora**: `sudo dnf install ./ufw-guard-<version>-1.x86_64.rpm`

### From Source
```bash
cargo build --release
sudo install -m 755 target/release/ufw /usr/local/sbin/ufw
```

---

## Usage

```bash
# Rule commands require a comment:
ufw allow 22/tcp comment "Allow SSH ingress"

# Missing comments trigger an interactive prompt (or error in CI/CD):
ufw allow 80/tcp

# Emergency bypass:
ufw allow 443/tcp --force-no-comment
UFW_GUARD_BYPASS=1 ufw allow 443/tcp

# Transparent pass-through for non-rule commands:
ufw status verbose
ufw reload
```

---

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
