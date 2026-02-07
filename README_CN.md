# VPS 首次开机安全加固

`vps-firstboot-hardening.sh` 用于新装 VPS 的快速安全初始化。

英文主文档：`README.md`

## 兼容环境
- Ubuntu 22.04 / 24.04
- Debian 12 / 13
- systemd 环境
- 需 `root` 权限执行

## 脚本会做什么
1. 通过 sysctl 禁用 IPv6（可选写入 GRUB `ipv6.disable=1`）。
2. 启用 BBR 并输出实际生效值。
3. 可选修改 SSH 端口（Drop-in 方式）。
4. 可选强制 SSH 仅密钥登录。
5. SSH 阶段支持快照与自动回滚。
6. 执行后输出验收信息（`sshd -T`、监听端口、sysctl）。

## 按需求保留的行为
- 保留 root 密钥登录：`PermitRootLogin prohibit-password`。
- 服务器自动生成密钥时，会把私钥打印到终端供复制。

## 本地运行
```bash
chmod +x vps-firstboot-hardening.sh
sudo ./vps-firstboot-hardening.sh
```

## GitHub 直接调用
与 `bash <(curl -sL ...)` 同类用法：
下方示例已使用你的仓库：`blueinx/vps-firstboot-hardening`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/main/vps-firstboot-hardening.sh)
```

带参数调用：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/main/vps-firstboot-hardening.sh) \
  --yes --port 51222 --pubkey-file /root/mykey.pub --grub-ipv6
```

固定版本（tag 或 commit）调用：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/<TAG_OR_COMMIT>/vps-firstboot-hardening.sh) --yes
```

如果当前 shell 不支持 `<(...)`：

```bash
curl -fsSL https://raw.githubusercontent.com/blueinx/vps-firstboot-hardening/main/vps-firstboot-hardening.sh -o /tmp/vps-firstboot-hardening.sh
bash /tmp/vps-firstboot-hardening.sh --yes
```

## 非交互示例
```bash
sudo ./vps-firstboot-hardening.sh --yes --port 51222 --pubkey-file /root/mykey.pub --grub-ipv6
```

```bash
sudo ./vps-firstboot-hardening.sh --yes --no-ipv6 --no-bbr --port 2222 --pubkey "ssh-ed25519 AAAA..."
```

## 参数说明
- `-y, --yes`：非交互执行，默认 Yes 项自动确认。
- `--allow-unsupported`：允许在不受支持系统上继续执行。
- `--no-ipv6`：跳过 IPv6 禁用。
- `--no-bbr`：跳过 BBR 启用。
- `--no-change-port`：跳过 SSH 端口修改。
- `--no-key-only`：跳过仅密钥登录加固。
- `--port <1-65535>`：设置 SSH 端口并启用改端口步骤。
- `--pubkey "<公钥>"`：直接传入公钥文本。
- `--pubkey-file <path>`：从文件读取公钥（支持多行）。
- `--grub-ipv6`：写入 GRUB `ipv6.disable=1`（需重启）。
- `--no-grub-ipv6`：不写入 GRUB（默认）。
- `-h, --help`：显示帮助。

## 重要提示
- 脚本不会修改防火墙规则，请自行放行 SSH 端口。
- 运行期间请保持当前 SSH 会话不断开，先开新窗口验证。
- 使用 `--grub-ipv6` 后需重启才会完全生效。
- 终端显示的私钥属于敏感信息，请妥善保存。

## 主要改动文件
- `/etc/ssh/sshd_config.d/99-vps-init-port.conf`
- `/etc/ssh/sshd_config.d/99-vps-init-keyonly.conf`
- `/etc/sysctl.d/99-disable-ipv6.conf`
- `/etc/sysctl.d/99-bbr.conf`
- `/root/.vps-init-backup/ssh_<timestamp>/`

## 回滚机制
- SSH 修改前会快照 `/etc/ssh`。
- SSH 阶段失败会自动回滚。
- 若自动回滚失败，请通过云控制台手动恢复。
