# VPS Firstboot Hardening

Harden a freshly installed VPS with one script: `vps-firstboot-hardening.sh`.

Chinese docs: `README_CN.md`

## Compatibility
- Ubuntu 22.04 / 24.04
- Debian 12 / 13
- systemd-based hosts
- Run as `root`

## What It Configures
1. Disable IPv6 via sysctl (optional GRUB `ipv6.disable=1`).
2. Enable BBR and verify runtime values.
3. Optionally change SSH port using drop-in config.
4. Optionally enforce SSH key-only login.
5. Snapshot and auto-rollback for SSH stage failures.
6. Post-run verification output (`sshd -T`, listening ports, sysctl values).

## Intentionally Preserved Behaviors
- Root key login is allowed: `PermitRootLogin prohibit-password`.
- If the server generates a key pair, the private key is printed to terminal for copy.

## Quick Start (Local File)
```bash
chmod +x vps-firstboot-hardening.sh
sudo ./vps-firstboot-hardening.sh
```

## Run Directly From GitHub Raw
Use Bash process substitution (same style as `bash <(curl -sL ...)`):
Repository used below: `blueinx/vps-firstboot-hardening`.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/main/vps-firstboot-hardening.sh)
```

With arguments:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/main/vps-firstboot-hardening.sh) \
  --yes --port 51222 --pubkey-file /root/mykey.pub --grub-ipv6
```

Pin to a tag or commit:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/<TAG_OR_COMMIT>/vps-firstboot-hardening.sh) --yes
```

If your shell does not support `<(...)`:

```bash
curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/main/vps-firstboot-hardening.sh -o /tmp/vps-firstboot-hardening.sh
bash /tmp/vps-firstboot-hardening.sh --yes
```

## Non-Interactive Examples
```bash
sudo ./vps-firstboot-hardening.sh --yes --port 51222 --pubkey-file /root/mykey.pub --grub-ipv6
```

```bash
sudo ./vps-firstboot-hardening.sh --yes --no-ipv6 --no-bbr --port 2222 --pubkey "ssh-ed25519 AAAA..."
```

## Arguments
- `-y, --yes`: non-interactive mode; default-yes prompts are auto-approved.
- `--allow-unsupported`: continue on unsupported OS versions.
- `--no-ipv6`: skip IPv6 disable.
- `--no-bbr`: skip BBR enable.
- `--no-change-port`: skip SSH port change.
- `--no-key-only`: skip key-only hardening.
- `--port <1-65535>`: set SSH port and enable the port-change step.
- `--pubkey "<key>"`: pass SSH public key directly.
- `--pubkey-file <path>`: load SSH public keys from file.
- `--grub-ipv6`: write GRUB `ipv6.disable=1` (reboot required).
- `--no-grub-ipv6`: skip GRUB update (default).
- `-h, --help`: show help.

## Important Notes
- The script does not change firewall rules. Open your SSH port manually.
- Keep your current SSH session open until you verify a new login works.
- If `--grub-ipv6` is used, reboot is required for full effect.
- Treat printed private keys as sensitive material.

## Managed Files
- `/etc/ssh/sshd_config.d/99-vps-init-port.conf`
- `/etc/ssh/sshd_config.d/99-vps-init-keyonly.conf`
- `/etc/sysctl.d/99-disable-ipv6.conf`
- `/etc/sysctl.d/99-bbr.conf`
- `/root/.vps-init-backup/ssh_<timestamp>/`

## Rollback Behavior
- Before SSH modifications, `/etc/ssh` is snapshotted.
- On SSH-stage failure, auto-rollback is triggered.
- If rollback fails, recover manually from console access.
