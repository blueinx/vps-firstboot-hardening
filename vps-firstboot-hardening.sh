#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="2.0.0"

# ===================== UI =====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $*"; }
ok() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[FAIL]${NC} $*" >&2; }
die() { err "$*"; exit 1; }

# ===================== Defaults =====================
ASSUME_YES=0
ALLOW_UNSUPPORTED=0

STEP_IPV6="ask"
STEP_BBR="ask"
STEP_PORT="ask"
STEP_KEYONLY="ask"
STEP_GRUB_IPV6="ask"

PORT_SET_BY_ARG=0

SSH_PORT="51222"
PUBKEY_TEXT=""
PUBKEY_FILE=""

OS_ID=""
OS_VERSION_ID=""
OS_PRETTY=""

SSH_SERVICE=""
SSH_STAGE_ACTIVE=0
SSH_ROLLBACK_IN_PROGRESS=0
SSH_SNAPSHOT_DIR=""

SSHD_MAIN="/etc/ssh/sshd_config"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
PORT_DROPIN="${SSHD_DROPIN_DIR}/99-vps-init-port.conf"
HARDEN_DROPIN="${SSHD_DROPIN_DIR}/99-vps-init-keyonly.conf"

# ===================== Error / Rollback =====================
rollback_ssh() {
  SSH_ROLLBACK_IN_PROGRESS=1

  set +e
  local rc=0

  if [[ -z "${SSH_SNAPSHOT_DIR}" || ! -d "${SSH_SNAPSHOT_DIR}" ]]; then
    err "未找到 SSH 回滚快照，无法自动回滚。"
    rc=1
  else
    warn "正在执行 SSH 自动回滚..."
    rm -f "${PORT_DROPIN}" "${HARDEN_DROPIN}" || rc=1
    cp -a "${SSH_SNAPSHOT_DIR}/." /etc/ssh/ || rc=1

    if command -v sshd >/dev/null 2>&1; then
      sshd -t >/dev/null 2>&1
      if [[ $? -ne 0 ]]; then
        err "回滚后 sshd -t 仍失败。"
        rc=1
      fi
    fi

    systemctl restart "${SSH_SERVICE}" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      err "回滚后 SSH 服务重启失败。"
      rc=1
    fi
  fi

  set -e

  if [[ ${rc} -eq 0 ]]; then
    ok "SSH 配置已自动回滚成功。"
  else
    err "SSH 自动回滚失败，请通过控制台手动修复 /etc/ssh 下配置。"
  fi

  SSH_ROLLBACK_IN_PROGRESS=0
  return "${rc}"
}

on_err() {
  local rc=$?
  local line="${BASH_LINENO[0]:-?}"
  local cmd="${BASH_COMMAND:-?}"

  if [[ ${SSH_STAGE_ACTIVE} -eq 1 && ${SSH_ROLLBACK_IN_PROGRESS} -eq 0 ]]; then
    err "SSH 配置阶段失败，已触发自动回滚。"
    rollback_ssh || true
    SSH_STAGE_ACTIVE=0
  fi

  err "发生错误：exit=${rc}, line=${line}, cmd=${cmd}"
  exit "${rc}"
}
trap on_err ERR

# ===================== Helpers =====================
print_usage() {
  cat <<'EOF'
用法:
  sudo bash vps-firstboot-hardening.sh [选项]

说明:
  交互模式默认逐项确认。
  非交互推荐配合 --yes + 显式参数。

选项:
  -y, --yes                非交互，所有“默认 Yes”的步骤自动执行
  --allow-unsupported      允许在非 Ubuntu 22/24、Debian 12/13 上继续执行

  --no-ipv6                跳过 IPv6 禁用
  --no-bbr                 跳过 BBR 开启
  --no-change-port         跳过 SSH 端口修改
  --no-key-only            跳过 SSH 仅密钥登录加固

  --port <1-65535>         指定 SSH 端口（自动启用“修改端口”步骤）
  --pubkey "<公钥文本>"      指定 SSH 公钥（自动启用“仅密钥登录”步骤）
  --pubkey-file <路径>      从文件读取 SSH 公钥（可多行）

  --grub-ipv6              启用 GRUB 参数 ipv6.disable=1（需重启）
  --no-grub-ipv6           禁用 GRUB 参数写入（默认）

  -h, --help               显示帮助

示例:
  sudo bash vps-firstboot-hardening.sh
  sudo bash vps-firstboot-hardening.sh --yes --port 51222 --pubkey-file /root/mykey.pub --grub-ipv6
  sudo bash vps-firstboot-hardening.sh --yes --no-ipv6 --no-bbr --port 2222
EOF
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "请使用 root 运行该脚本。"
}

backup_file() {
  local f="$1"
  [[ -f "${f}" ]] || return 0
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  cp -a "${f}" "${f}.bak.${ts}"
  ok "已备份：${f} -> ${f}.bak.${ts}"
}

ask_yn_default_yes() {
  local prompt="$1" ans
  read -r -p "$(echo -e "${BLUE}${prompt} [Y/n]（回车默认 Y）: ${NC}")" ans || true
  ans="${ans:-Y}"
  case "${ans}" in
    Y|y|yes|YES) return 0 ;;
    N|n|no|NO) return 1 ;;
    *) warn "输入无效，按默认 Y 处理"; return 0 ;;
  esac
}

ask_yn_default_no() {
  local prompt="$1" ans
  read -r -p "$(echo -e "${BLUE}${prompt} [y/N]（回车默认 N）: ${NC}")" ans || true
  ans="${ans:-N}"
  case "${ans}" in
    Y|y|yes|YES) return 0 ;;
    N|n|no|NO) return 1 ;;
    *) warn "输入无效，按默认 N 处理"; return 1 ;;
  esac
}

ask_input_default() {
  local prompt="$1" def="$2" ans
  read -r -p "$(echo -e "${BLUE}${prompt}（回车默认 ${def}）: ${NC}")" ans || true
  echo "${ans:-${def}}"
}

resolve_step() {
  local mode="$1" prompt="$2" default_yes="$3"
  case "${mode}" in
    yes) return 0 ;;
    no) return 1 ;;
    ask)
      if [[ ${ASSUME_YES} -eq 1 ]]; then
        if [[ "${default_yes}" == "yes" ]]; then
          return 0
        else
          return 1
        fi
      fi
      if [[ "${default_yes}" == "yes" ]]; then
        ask_yn_default_yes "${prompt}"
      else
        ask_yn_default_no "${prompt}"
      fi
      return $?
      ;;
    *)
      die "内部错误：未知步骤状态 ${mode}"
      ;;
  esac
}

is_valid_port() {
  local p="$1"
  [[ "${p}" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

validate_pubkey_line() {
  local key="$1"
  local tmp
  tmp="$(mktemp)"
  printf '%s\n' "${key}" > "${tmp}"
  if ssh-keygen -l -f "${tmp}" >/dev/null 2>&1; then
    rm -f "${tmp}"
    return 0
  fi
  rm -f "${tmp}"
  return 1
}

append_pubkey_if_missing() {
  local key="$1"
  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  if ! grep -qxF "${key}" /root/.ssh/authorized_keys; then
    echo "${key}" >> /root/.ssh/authorized_keys
    ok "已追加公钥到 /root/.ssh/authorized_keys"
  else
    info "公钥已存在于 authorized_keys，跳过。"
  fi
}

# ===================== Args =====================
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes)
        ASSUME_YES=1
        shift
        ;;
      --allow-unsupported)
        ALLOW_UNSUPPORTED=1
        shift
        ;;
      --no-ipv6)
        STEP_IPV6="no"
        shift
        ;;
      --no-bbr)
        STEP_BBR="no"
        shift
        ;;
      --no-change-port)
        STEP_PORT="no"
        shift
        ;;
      --no-key-only)
        STEP_KEYONLY="no"
        shift
        ;;
      --port)
        [[ $# -ge 2 ]] || die "--port 需要一个参数"
        SSH_PORT="$2"
        STEP_PORT="yes"
        PORT_SET_BY_ARG=1
        shift 2
        ;;
      --pubkey)
        [[ $# -ge 2 ]] || die "--pubkey 需要一个参数"
        PUBKEY_TEXT="$2"
        STEP_KEYONLY="yes"
        shift 2
        ;;
      --pubkey-file)
        [[ $# -ge 2 ]] || die "--pubkey-file 需要一个参数"
        PUBKEY_FILE="$2"
        STEP_KEYONLY="yes"
        shift 2
        ;;
      --grub-ipv6)
        STEP_GRUB_IPV6="yes"
        shift
        ;;
      --no-grub-ipv6)
        STEP_GRUB_IPV6="no"
        shift
        ;;
      -h|--help)
        print_usage
        exit 0
        ;;
      *)
        die "未知参数：$1（使用 --help 查看）"
        ;;
    esac
  done

  if [[ -n "${PUBKEY_TEXT}" && -n "${PUBKEY_FILE}" ]]; then
    die "--pubkey 与 --pubkey-file 不能同时使用"
  fi

  if [[ "${STEP_PORT}" == "yes" ]]; then
    is_valid_port "${SSH_PORT}" || die "端口无效：${SSH_PORT}"
  fi

  if [[ -n "${PUBKEY_FILE}" && ! -f "${PUBKEY_FILE}" ]]; then
    die "公钥文件不存在：${PUBKEY_FILE}"
  fi
}

# ===================== Environment Checks =====================
detect_os() {
  [[ -r /etc/os-release ]] || die "无法识别系统：缺少 /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release

  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_PRETTY="${PRETTY_NAME:-unknown}"

  info "检测到系统：${OS_PRETTY}"

  local major="${OS_VERSION_ID%%.*}"
  case "${OS_ID}:${major}" in
    ubuntu:22|ubuntu:24|debian:12|debian:13)
      ok "系统版本在支持矩阵内（Ubuntu 22/24, Debian 12/13）"
      ;;
    *)
      if [[ ${ALLOW_UNSUPPORTED} -eq 1 ]]; then
        warn "当前系统不在官方支持矩阵内，但你已启用 --allow-unsupported，继续执行。"
      else
        die "当前系统不在支持矩阵内。仅支持 Ubuntu 22/24、Debian 12/13。可加 --allow-unsupported 强制继续。"
      fi
      ;;
  esac
}

detect_ssh_service() {
  local units
  units="$(
    systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
    | awk '{print $1}' \
    || true
  )"

  if echo "${units}" | grep -qx 'ssh.service'; then
    SSH_SERVICE="ssh"
    return 0
  fi
  if echo "${units}" | grep -qx 'sshd.service'; then
    SSH_SERVICE="sshd"
    return 0
  fi

  # Fallback: 某些发行版会保留 unit 但 list-unit-files 输出异常。
  if systemctl status ssh >/dev/null 2>&1 || systemctl cat ssh >/dev/null 2>&1; then
    SSH_SERVICE="ssh"
    return 0
  fi
  if systemctl status sshd >/dev/null 2>&1 || systemctl cat sshd >/dev/null 2>&1; then
    SSH_SERVICE="sshd"
    return 0
  fi

  # 仅检测到 socket 时，优先按 ssh 处理（Debian/Ubuntu 常见）。
  if systemctl list-unit-files --type=socket --no-legend --no-pager 2>/dev/null \
    | awk '{print $1}' | grep -qx 'ssh.socket'; then
    SSH_SERVICE="ssh"
    warn "检测到 ssh.socket，将使用 ssh.service 执行重载/重启。"
    return 0
  fi

  die "未找到可用的 SSH 服务单元（ssh/sshd）。"
}

preflight_checks() {
  local required=(
    systemctl
    sshd
    ssh-keygen
    sysctl
    grep
    sed
    awk
    cp
    chmod
    chown
    mkdir
    mktemp
    date
    cat
    rm
  )

  local missing=()
  local c
  for c in "${required[@]}"; do
    if ! command_exists "${c}"; then
      missing+=("${c}")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    die "缺少必要命令：${missing[*]}"
  fi

  systemctl list-unit-files --type=service --no-pager >/dev/null 2>&1 || die "systemctl 不可用（需要 systemd 环境）"
  detect_ssh_service
  [[ -f "${SSHD_MAIN}" ]] || die "未找到 SSH 主配置：${SSHD_MAIN}"
  mkdir -p /root/.vps-init-backup
}

# ===================== Step 1: IPv6 =====================
disable_ipv6() {
  info "配置：禁用 IPv6（sysctl）"
  local conf="/etc/sysctl.d/99-disable-ipv6.conf"
  backup_file "${conf}"

  cat > "${conf}" <<'EOF'
# Managed by vps-firstboot-hardening.sh
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

  sysctl --system >/dev/null
  ok "IPv6 配置已写入：${conf}"

  local all_v default_v lo_v
  all_v="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || true)"
  default_v="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || true)"
  lo_v="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || true)"
  info "当前内核值：all=${all_v}, default=${default_v}, lo=${lo_v}"

  if resolve_step "${STEP_GRUB_IPV6}" "是否写入 GRUB 参数 ipv6.disable=1（更彻底，需重启）？" "no"; then
    if [[ -f /etc/default/grub ]]; then
      backup_file /etc/default/grub
      if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
        if ! grep -q 'ipv6.disable=1' /etc/default/grub; then
          sed -i 's/^\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 ipv6.disable=1"/' /etc/default/grub
        fi
      else
        echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub
      fi

      if command_exists update-grub; then
        update-grub >/dev/null
        ok "GRUB 已更新，重启后会更彻底生效。"
      else
        warn "未找到 update-grub，请手动更新引导配置。"
      fi
    else
      warn "未找到 /etc/default/grub，已跳过 GRUB 级禁用。"
    fi
  fi
}

# ===================== Step 2: BBR =====================
enable_bbr() {
  info "配置：开启 BBR"
  local conf="/etc/sysctl.d/99-bbr.conf"
  backup_file "${conf}"

  cat > "${conf}" <<'EOF'
# Managed by vps-firstboot-hardening.sh
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  if command_exists modprobe; then
    modprobe tcp_bbr >/dev/null 2>&1 || warn "modprobe tcp_bbr 失败，可能内核未启用模块。"
  else
    warn "未找到 modprobe，跳过内核模块加载。"
  fi

  sysctl --system >/dev/null

  local cc qdisc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  if [[ "${cc}" == "bbr" ]]; then
    ok "BBR 已启用（tcp_congestion_control=${cc}, default_qdisc=${qdisc}）"
  else
    warn "未确认 BBR 生效（当前 tcp_congestion_control=${cc}），可能是内核/环境限制。"
  fi
}

# ===================== Step 3/4: SSH =====================
snapshot_ssh() {
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  SSH_SNAPSHOT_DIR="/root/.vps-init-backup/ssh_${ts}"
  mkdir -p "${SSH_SNAPSHOT_DIR}"
  cp -a /etc/ssh/. "${SSH_SNAPSHOT_DIR}/"
  ok "已创建 SSH 回滚快照：${SSH_SNAPSHOT_DIR}"
}

ensure_sshd_dropin_include() {
  mkdir -p "${SSHD_DROPIN_DIR}"
  chmod 755 "${SSHD_DROPIN_DIR}"

  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]*#.*)?$' "${SSHD_MAIN}"; then
    backup_file "${SSHD_MAIN}"
    {
      echo
      echo "# Added by ${SCRIPT_NAME}"
      echo "Include /etc/ssh/sshd_config.d/*.conf"
    } >> "${SSHD_MAIN}"
    ok "已在 ${SSHD_MAIN} 追加 Include /etc/ssh/sshd_config.d/*.conf"
  fi
}

port_in_use() {
  local port="$1"
  if command_exists ss; then
    if ss -lntH | awk '{print $4}' | grep -qE "[:.]${port}$"; then
      return 0
    fi
  fi
  return 1
}

prepare_ssh_port_config() {
  local port="$1"
  is_valid_port "${port}" || die "SSH 端口无效：${port}"

  if port_in_use "${port}"; then
    warn "检测到端口 ${port} 可能已被占用。"
    if [[ ${ASSUME_YES} -eq 0 ]]; then
      ask_yn_default_no "是否仍继续使用端口 ${port}？" || die "你取消了端口修改。"
    else
      warn "--yes 模式下已自动继续。"
    fi
  fi

  backup_file "${PORT_DROPIN}"
  cat > "${PORT_DROPIN}" <<EOF
# Managed by ${SCRIPT_NAME}
Port ${port}
EOF
  chmod 644 "${PORT_DROPIN}"
  ok "SSH 端口配置已写入：${PORT_DROPIN}（Port ${port}）"
}

prepare_root_ssh_dir() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  chown root:root /root/.ssh

  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  chown root:root /root/.ssh/authorized_keys
}

setup_key_only_config() {
  prepare_root_ssh_dir

  local -a keys=()
  local line pubkey_input

  if [[ -n "${PUBKEY_FILE}" ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
      line="${line%$'\r'}"
      [[ -z "${line}" ]] && continue
      [[ "${line}" =~ ^[[:space:]]*# ]] && continue
      keys+=("${line}")
    done < "${PUBKEY_FILE}"
    [[ ${#keys[@]} -gt 0 ]] || die "公钥文件为空或只有注释：${PUBKEY_FILE}"
  elif [[ -n "${PUBKEY_TEXT}" ]]; then
    keys+=("${PUBKEY_TEXT}")
  else
    if [[ ${ASSUME_YES} -eq 0 ]]; then
      echo
      warn "为避免锁死，建议粘贴你本地已有 SSH 公钥。"
      warn "直接回车将由服务器生成 Ed25519 密钥，并打印私钥供你复制。"
      echo
      read -r -p "$(echo -e "${BLUE}请输入 SSH 公钥（ssh-ed25519/ssh-rsa/...），或直接回车自动生成: ${NC}")" pubkey_input || true
      if [[ -n "${pubkey_input}" ]]; then
        keys+=("${pubkey_input}")
      fi
    fi
  fi

  if [[ ${#keys[@]} -gt 0 ]]; then
    local key
    for key in "${keys[@]}"; do
      validate_pubkey_line "${key}" || die "检测到无效公钥：${key}"
      append_pubkey_if_missing "${key}"
    done
  else
    if [[ -f /root/.ssh/id_ed25519 ]]; then
      warn "检测到 /root/.ssh/id_ed25519 已存在，跳过生成。"
    else
      info "生成 Ed25519 密钥对：/root/.ssh/id_ed25519"
      ssh-keygen -t ed25519 -a 64 -f /root/.ssh/id_ed25519 -N "" -C "root@$(hostname)-$(date +%F)" >/dev/null
      chmod 600 /root/.ssh/id_ed25519
      chown root:root /root/.ssh/id_ed25519
      ok "已生成密钥对。"
    fi

    [[ -f /root/.ssh/id_ed25519.pub ]] || die "缺少 /root/.ssh/id_ed25519.pub"
    local gen_pub
    gen_pub="$(cat /root/.ssh/id_ed25519.pub)"
    validate_pubkey_line "${gen_pub}" || die "自动生成公钥校验失败。"
    append_pubkey_if_missing "${gen_pub}"

    echo
    warn "================= 重要：请立刻保存下面这段【私钥】到你本地（文件权限 600） ================="
    cat /root/.ssh/id_ed25519
    warn "================= 私钥到此结束。请勿泄露。建议保存后立刻离线备份。 ================="
    echo
  fi

  if ! grep -qE '^(ssh-|ecdsa-sha2-nistp|sk-ssh-|sk-ecdsa-)' /root/.ssh/authorized_keys; then
    die "authorized_keys 中未检测到有效 SSH 公钥。为避免锁死，脚本中止。"
  fi

  backup_file "${HARDEN_DROPIN}"
  cat > "${HARDEN_DROPIN}" <<'EOF'
# Managed by vps-firstboot-hardening.sh - key-only hardening
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
  chmod 644 "${HARDEN_DROPIN}"

  ok "SSH 加固配置已写入：${HARDEN_DROPIN}（保留 root 密钥登录）"
}

test_sshd() {
  sshd -t
}

reload_sshd() {
  systemctl reload "${SSH_SERVICE}" >/dev/null 2>&1 || systemctl restart "${SSH_SERVICE}" >/dev/null 2>&1
  systemctl is-active --quiet "${SSH_SERVICE}"
  ok "SSH 服务已重载/重启：${SSH_SERVICE}"
}

apply_ssh_stage() {
  local run_port="$1" run_key="$2"
  if [[ "${run_port}" -eq 0 && "${run_key}" -eq 0 ]]; then
    return 0
  fi

  SSH_STAGE_ACTIVE=1
  snapshot_ssh
  ensure_sshd_dropin_include

  if [[ "${run_port}" -eq 1 ]]; then
    prepare_ssh_port_config "${SSH_PORT}"
    warn "请确认你已放行 ${SSH_PORT}/tcp（本脚本不改防火墙）。"
  fi
  if [[ "${run_key}" -eq 1 ]]; then
    setup_key_only_config
  fi

  test_sshd
  reload_sshd

  SSH_STAGE_ACTIVE=0
  ok "SSH 配置已应用并验证通过。"
}

# ===================== Step 7: Post Checks =====================
show_post_checks() {
  echo
  echo -e "${GREEN}====================== 执行后验收 ======================${NC}"

  echo -e "${BLUE}[1] SSH 服务状态${NC}"
  if systemctl is-active --quiet "${SSH_SERVICE}"; then
    ok "SSH 服务状态：active (${SSH_SERVICE})"
  else
    err "SSH 服务状态：inactive/failed (${SSH_SERVICE})"
  fi

  echo -e "${BLUE}[2] SSH 生效配置（sshd -T）${NC}"
  if command_exists sshd; then
    sshd -T | awk '
      $1=="port" ||
      $1=="pubkeyauthentication" ||
      $1=="passwordauthentication" ||
      $1=="kbdinteractiveauthentication" ||
      $1=="challengeresponseauthentication" ||
      $1=="permitrootlogin" ||
      $1=="maxauthtries" ||
      $1=="logingracetime" ||
      $1=="clientaliveinterval" ||
      $1=="clientalivecountmax" {print "  " $0}
    '
  else
    warn "未找到 sshd，无法输出 sshd -T。"
  fi

  echo -e "${BLUE}[3] SSH 监听端口（ss）${NC}"
  if command_exists ss; then
    local ports p found=0
    ports="$(sshd -T | awk '$1=="port"{print $2}')"
    for p in ${ports}; do
      if ss -lntH | awk -v port="${p}" '$4 ~ ("[:.]" port "$") {print "  " $0}' | grep -q .; then
        ss -lntH | awk -v port="${p}" '$4 ~ ("[:.]" port "$") {print "  " $0}'
        found=1
      fi
    done
    if [[ ${found} -eq 0 ]]; then
      warn "未在 ss 输出中匹配到 sshd -T 声明的端口。"
    fi
  else
    warn "未找到 ss，无法输出监听端口。"
  fi

  echo -e "${BLUE}[4] Sysctl 当前值${NC}"
  local kv v
  for kv in \
    net.ipv6.conf.all.disable_ipv6 \
    net.ipv6.conf.default.disable_ipv6 \
    net.ipv6.conf.lo.disable_ipv6 \
    net.core.default_qdisc \
    net.ipv4.tcp_congestion_control
  do
    v="$(sysctl -n "${kv}" 2>/dev/null || echo 'N/A')"
    echo "  ${kv} = ${v}"
  done

  echo -e "${GREEN}========================================================${NC}"
  echo
}

# ===================== Main =====================
main() {
  parse_args "$@"

  echo -e "${BLUE}==========================================================${NC}"
  echo -e "${BLUE}  VPS 安全初始化脚本 v${SCRIPT_VERSION}  ${NC}"
  echo -e "${BLUE}  兼容目标: Ubuntu 22/24, Debian 12/13${NC}"
  echo -e "${BLUE}==========================================================${NC}"
  echo -e "核心动作："
  echo -e "  1) IPv6 禁用（sysctl + 可选 GRUB）"
  echo -e "  2) BBR 启用"
  echo -e "  3) SSH 端口修改（可选）"
  echo -e "  4) SSH 仅密钥登录（保留 root 密钥登录）"
  echo

  need_root
  detect_os
  preflight_checks

  local run_ipv6=0
  local run_bbr=0
  local run_port=0
  local run_key=0
  local summary_port="22"

  if resolve_step "${STEP_IPV6}" "1) 是否禁用 IPv6？" "yes"; then
    run_ipv6=1
  fi
  if resolve_step "${STEP_BBR}" "2) 是否开启 BBR？" "yes"; then
    run_bbr=1
  fi
  if resolve_step "${STEP_PORT}" "3) 是否修改 SSH 端口？" "yes"; then
    run_port=1
  fi
  if resolve_step "${STEP_KEYONLY}" "4) 是否配置 SSH Key 并强制仅密钥登录？" "yes"; then
    run_key=1
  fi

  if [[ ${run_port} -eq 1 && ${PORT_SET_BY_ARG} -eq 0 ]]; then
    SSH_PORT="$(ask_input_default "请输入新的 SSH 端口" "${SSH_PORT}")"
    is_valid_port "${SSH_PORT}" || die "SSH 端口无效：${SSH_PORT}"
  fi

  if [[ ${run_ipv6} -eq 1 ]]; then
    disable_ipv6
  else
    info "已跳过 IPv6 禁用。"
  fi

  if [[ ${run_bbr} -eq 1 ]]; then
    enable_bbr
  else
    info "已跳过 BBR 启用。"
  fi

  apply_ssh_stage "${run_port}" "${run_key}"
  summary_port="$(sshd -T | awk '$1=="port"{print $2; exit}' 2>/dev/null || echo "${summary_port}")"

  show_post_checks

  echo -e "${GREEN}====================== 执行完成 ======================${NC}"
  echo -e "${BLUE}重要提醒：${NC}"
  echo -e "  1) 脚本不会修改防火墙，请确认已放行 ${summary_port}/tcp。"
  echo -e "  2) 不要立即断开当前会话，先新开窗口验证登录。"
  echo -e "  3) 测试命令：ssh -p ${summary_port} root@<服务器IP>"
  echo -e "  4) 若写入 GRUB 禁用 IPv6，请按需重启生效。"
  echo -e "${GREEN}======================================================${NC}"
}

main "$@"
