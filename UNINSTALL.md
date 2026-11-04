# Uninstalling `ufw-guard`

Removing `ufw-guard` restores direct execution of upstream `/usr/sbin/ufw`. All existing firewall rules and comments remain intact.

## 1. Remove by Installation Method

### Debian / Ubuntu (`.deb`)
```bash
sudo apt remove ufw-guard && hash -r
```

### RHEL / Fedora (`.rpm`)
```bash
sudo dnf remove ufw-guard && hash -r
```

### One-Liner (`install.sh`) / Standalone Binary / From Source
```bash
sudo rm -f /usr/local/sbin/ufw && hash -r
```

### Cargo
```bash
cargo uninstall ufw-guard
```

---

## 2. Verify Upstream Restoration

Confirm that your shell now resolves directly to `/usr/sbin/ufw`:

```bash
which ufw
# Expected output: /usr/sbin/ufw
```
