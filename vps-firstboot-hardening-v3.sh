#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="3.0.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="/var/log/vps-firstboot-hardening.log"
BACKUP_ROOT="/root/.vps-init-backup"
RUN_ID="$(date +%Y%m%d_%H%M%S)_$$"

ASSUME_YES=0
ALLOW_UNSUPPORTED=0
DRY_RUN=0
AUDIT_ONLY=0
ACK_FIREWALL_RISK=0
UFW_ALLOW_SSH_PORT=0
DISABLE_SSH_SOCKET=0

STEP_IPV6="ask"
STEP_BBR="ask"
STEP_PORT="ask"
STEP_KEYONLY="ask"
STEP_GRUB_IPV6="ask"

SSH_PORT="51222"
PORT_SET_BY_ARG=0
PUBKEY_TEXT=""
PUBKEY_FILE=""
CREATE_USER=""
DISABLE_ROOT_LOGIN=0

SAW_PORT_ARG=0
SAW_NO_PORT=0
SAW_PUBKEY_ARG=0
SAW_NO_KEYONLY=0
SAW_GRUB_YES=0
SAW_GRUB_NO=0

OS_ID=""
OS_VERSION_ID=""
OS_PRETTY=""
SSH_SERVICE=""
SSHD_BIN=""
SSH_SOCKET_ACTIVE=0

SSHD_MAIN="/etc/ssh/sshd_config"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
PORT_DROPIN="${SSHD_DROPIN_DIR}/20-vps-init-port.conf"
HARDEN_DROPIN="${SSHD_DROPIN_DIR}/20-vps-init-keyonly.conf"

CURRENT_STAGE=""
SSH_SNAPSHOT_DIR=""
ROLLBACK_PATHS=()
ROLLBACK_BACKUPS=()
ROLLBACK_EXISTED=()

plain_log() {
  [[ ${DRY_RUN} -eq 1 ]] && return 0
  [[ -n "${LOG_FILE}" ]] || return 0
  printf '%s %s\n' "$(date '+%F %T')" "$*" >> "${LOG_FILE}" 2>/dev/null || true
}

info() { echo -e "${BLUE}[INFO]${NC} $*"; plain_log "[INFO] $*"; }
ok() { echo -e "${GREEN}[ OK ]${NC} $*"; plain_log "[ OK ] $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; plain_log "[WARN] $*"; }
err() { echo -e "${RED}[FAIL]${NC} $*" >&2; plain_log "[FAIL] $*"; }
die() { err "$*"; exit 1; }

print_usage() {
  cat <<'EOF'
用法:
  sudo bash vps-firstboot-hardening.sh [选项]

核心模式:
  -y, --yes                    非交互模式；默认 Yes 项自动执行
  --dry-run                    只展示计划，不写入系统
  --audit-only                 只审计当前系统状态，不修改系统
  --allow-unsupported          允许在非 Ubuntu 22/24、Debian 12/13 上继续执行

步骤开关:
  --no-ipv6                    跳过 IPv6 禁用
  --no-bbr                     跳过 BBR 开启
  --no-change-port             跳过 SSH 端口修改
  --no-key-only                跳过 SSH 仅密钥登录加固
  --grub-ipv6                  写入 GRUB ipv6.disable=1（需重启）
  --no-grub-ipv6               不写入 GRUB（默认）

SSH:
  --port <1-65535>             指定 SSH 端口
  --pubkey "<公钥文本>"          指定 SSH 公钥
  --pubkey-file <路径>          从文件读取 SSH 公钥（支持多行）
  --ack-firewall-risk          确认已处理云防火墙/安全组/系统防火墙风险
  --ufw-allow-ssh-port         如果 ufw active，自动放行新 SSH 端口
  --disable-ssh-socket         修改端口时，如 ssh.socket active，则禁用 socket activation

用户增强:
  --create-user <用户名>        创建 sudo 用户，并复制当前 authorized_keys
  --disable-root-login         禁止 root SSH 登录；必须配合 --create-user

示例:
  sudo bash vps-firstboot-hardening.sh
  sudo bash vps-firstboot-hardening.sh --audit-only
  sudo bash vps-firstboot-hardening.sh --dry-run --port 51222 --pubkey-file /root/id.pub
  sudo bash vps-firstboot-hardening.sh --yes --port 51222 --pubkey-file /root/id.pub --ack-firewall-risk
  sudo bash vps-firstboot-hardening.sh --yes --pubkey-file /root/id.pub --create-user deploy --disable-root-login
EOF
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "请使用 root 运行该脚本。"
}

is_valid_port() {
  local p="$1"
  [[ "${p}" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

is_valid_username() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
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
        [[ "${default_yes}" == "yes" ]]
        return $?
      fi
      if [[ "${default_yes}" == "yes" ]]; then
        ask_yn_default_yes "${prompt}"
      else
        ask_yn_default_no "${prompt}"
      fi
      ;;
    *) die "内部错误：未知步骤状态 ${mode}" ;;
  esac
}

start_stage() {
  CURRENT_STAGE="$1"
  ROLLBACK_PATHS=()
  ROLLBACK_BACKUPS=()
  ROLLBACK_EXISTED=()
}

end_stage() {
  CURRENT_STAGE=""
  ROLLBACK_PATHS=()
  ROLLBACK_BACKUPS=()
  ROLLBACK_EXISTED=()
}

safe_backup_name() {
  local p="$1"
  p="${p#/}"
  p="${p//\//__}"
  echo "${p}"
}

backup_for_rollback() {
  local path="$1" name backup
  [[ ${DRY_RUN} -eq 1 ]] && return 0
  mkdir -p "${BACKUP_ROOT}/files_${RUN_ID}"
  chmod 700 "${BACKUP_ROOT}" "${BACKUP_ROOT}/files_${RUN_ID}"
  name="$(safe_backup_name "${path}")"
  backup="${BACKUP_ROOT}/files_${RUN_ID}/${name}"
  if [[ -e "${path}" ]]; then
    cp -a "${path}" "${backup}"
    ROLLBACK_EXISTED+=("1")
  else
    ROLLBACK_EXISTED+=("0")
  fi
  ROLLBACK_PATHS+=("${path}")
  ROLLBACK_BACKUPS+=("${backup}")
}

rollback_files() {
  [[ ${DRY_RUN} -eq 1 ]] && return 0
  local i path backup existed
  for (( i=${#ROLLBACK_PATHS[@]}-1; i>=0; i-- )); do
    path="${ROLLBACK_PATHS[$i]}"
    backup="${ROLLBACK_BACKUPS[$i]}"
    existed="${ROLLBACK_EXISTED[$i]}"
    if [[ "${existed}" == "1" ]]; then
      cp -a "${backup}" "${path}" || true
      warn "已回滚文件：${path}"
    else
      rm -f "${path}" || true
      warn "已移除本次新建文件：${path}"
    fi
  done
}

write_file_atomic() {
  local target="$1" mode="$2" content="$3" dir tmp
  if [[ ${DRY_RUN} -eq 1 ]]; then
    info "[dry-run] 将写入 ${target} (mode ${mode})"
    return 0
  fi
  backup_for_rollback "${target}"
  dir="$(dirname "${target}")"
  mkdir -p "${dir}"
  tmp="$(mktemp "${target}.tmp.XXXXXX")"
  printf '%s' "${content}" > "${tmp}"
  chmod "${mode}" "${tmp}"
  mv "${tmp}" "${target}"
}

run_or_dry() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    info "[dry-run] $*"
    return 0
  fi
  "$@"
}

rollback_ssh() {
  [[ ${DRY_RUN} -eq 1 ]] && return 0
  if [[ -z "${SSH_SNAPSHOT_DIR}" || ! -d "${SSH_SNAPSHOT_DIR}" ]]; then
    err "未找到 SSH 快照，无法自动回滚。"
    return 1
  fi
  warn "正在回滚 SSH 配置..."
  rm -f "${PORT_DROPIN}" "${HARDEN_DROPIN}" || true
  cp -a "${SSH_SNAPSHOT_DIR}/." /etc/ssh/ || true
  "${SSHD_BIN}" -t >/dev/null 2>&1 || err "回滚后 sshd -t 仍失败。"
  systemctl restart "${SSH_SERVICE}" >/dev/null 2>&1 || err "回滚后 SSH 服务重启失败。"
  ok "SSH 配置已回滚。"
}

on_err() {
  local rc=$?
  local line="${BASH_LINENO[0]:-?}"
  local cmd="${BASH_COMMAND:-?}"
  if [[ -n "${CURRENT_STAGE}" ]]; then
    err "阶段 ${CURRENT_STAGE} 失败，开始回滚。"
    if [[ "${CURRENT_STAGE}" == "ssh" ]]; then
      rollback_ssh || true
    else
      rollback_files || true
    fi
  fi
  err "发生错误：exit=${rc}, line=${line}, cmd=${cmd}"
  exit "${rc}"
}
trap on_err ERR

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes) ASSUME_YES=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --audit-only) AUDIT_ONLY=1; shift ;;
      --allow-unsupported) ALLOW_UNSUPPORTED=1; shift ;;
      --no-ipv6) STEP_IPV6="no"; shift ;;
      --no-bbr) STEP_BBR="no"; shift ;;
      --no-change-port) STEP_PORT="no"; SAW_NO_PORT=1; shift ;;
      --no-key-only) STEP_KEYONLY="no"; SAW_NO_KEYONLY=1; shift ;;
      --port)
        [[ $# -ge 2 ]] || die "--port 需要参数"
        SSH_PORT="$2"; STEP_PORT="yes"; PORT_SET_BY_ARG=1; SAW_PORT_ARG=1; shift 2 ;;
      --pubkey)
        [[ $# -ge 2 ]] || die "--pubkey 需要参数"
        PUBKEY_TEXT="$2"; STEP_KEYONLY="yes"; SAW_PUBKEY_ARG=1; shift 2 ;;
      --pubkey-file)
        [[ $# -ge 2 ]] || die "--pubkey-file 需要参数"
        PUBKEY_FILE="$2"; STEP_KEYONLY="yes"; SAW_PUBKEY_ARG=1; shift 2 ;;
      --grub-ipv6) STEP_GRUB_IPV6="yes"; SAW_GRUB_YES=1; shift ;;
      --no-grub-ipv6) STEP_GRUB_IPV6="no"; SAW_GRUB_NO=1; shift ;;
      --ack-firewall-risk) ACK_FIREWALL_RISK=1; shift ;;
      --ufw-allow-ssh-port) UFW_ALLOW_SSH_PORT=1; shift ;;
      --disable-ssh-socket) DISABLE_SSH_SOCKET=1; shift ;;
      --create-user)
        [[ $# -ge 2 ]] || die "--create-user 需要用户名"
        CREATE_USER="$2"; shift 2 ;;
      --disable-root-login) DISABLE_ROOT_LOGIN=1; STEP_KEYONLY="yes"; shift ;;
      -h|--help) print_usage; exit 0 ;;
      *) die "未知参数：$1（使用 --help 查看）" ;;
    esac
  done

  [[ ${SAW_PORT_ARG} -eq 1 && ${SAW_NO_PORT} -eq 1 ]] && die "--port 与 --no-change-port 不能同时使用"
  [[ ${SAW_PUBKEY_ARG} -eq 1 && ${SAW_NO_KEYONLY} -eq 1 ]] && die "--pubkey/--pubkey-file 与 --no-key-only 不能同时使用"
  [[ ${SAW_GRUB_YES} -eq 1 && ${SAW_GRUB_NO} -eq 1 ]] && die "--grub-ipv6 与 --no-grub-ipv6 不能同时使用"
  [[ -n "${PUBKEY_TEXT}" && -n "${PUBKEY_FILE}" ]] && die "--pubkey 与 --pubkey-file 不能同时使用"
  if [[ "${STEP_PORT}" == "yes" ]]; then
    is_valid_port "${SSH_PORT}" || die "端口无效：${SSH_PORT}"
  fi
  [[ -n "${PUBKEY_FILE}" && ! -f "${PUBKEY_FILE}" ]] && die "公钥文件不存在：${PUBKEY_FILE}"
  if [[ -n "${CREATE_USER}" ]]; then
    is_valid_username "${CREATE_USER}" || die "用户名无效：${CREATE_USER}"
  fi
  [[ ${DISABLE_ROOT_LOGIN} -eq 1 && -z "${CREATE_USER}" ]] && die "--disable-root-login 必须配合 --create-user"
}

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
    ubuntu:22|ubuntu:24|debian:12|debian:13) ok "系统版本在支持矩阵内。" ;;
    *)
      [[ ${ALLOW_UNSUPPORTED} -eq 1 ]] || die "仅支持 Ubuntu 22/24、Debian 12/13；可加 --allow-unsupported 强制继续。"
      warn "当前系统不在支持矩阵内，继续执行。"
      ;;
  esac
}

detect_sshd_bin() {
  if command_exists sshd; then
    SSHD_BIN="$(command -v sshd)"
  elif [[ -x /usr/sbin/sshd ]]; then
    SSHD_BIN="/usr/sbin/sshd"
  else
    die "未找到 sshd。请先安装 openssh-server。"
  fi
}

detect_ssh_service() {
  local units
  units="$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}' || true)"
  if echo "${units}" | grep -qx 'ssh.service'; then
    SSH_SERVICE="ssh"
  elif echo "${units}" | grep -qx 'sshd.service'; then
    SSH_SERVICE="sshd"
  elif systemctl cat ssh >/dev/null 2>&1; then
    SSH_SERVICE="ssh"
  elif systemctl cat sshd >/dev/null 2>&1; then
    SSH_SERVICE="sshd"
  else
    die "未找到可用的 SSH 服务单元（ssh/sshd）。"
  fi

  if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    SSH_SOCKET_ACTIVE=1
  fi
}

preflight_checks() {
  local required=(systemctl ssh-keygen sysctl grep sed awk cp chmod chown mkdir mktemp date cat rm mv dirname id)
  local missing=() c
  for c in "${required[@]}"; do
    command_exists "${c}" || missing+=("${c}")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "缺少必要命令：${missing[*]}"
  command_exists ss || die "缺少必要命令：ss"
  if [[ -n "${CREATE_USER}" ]]; then
    command_exists useradd || die "缺少必要命令：useradd"
    command_exists usermod || die "缺少必要命令：usermod"
    command_exists getent || die "缺少必要命令：getent"
  fi
  command_exists flock || warn "未找到 flock，无法启用并发运行锁。"
  detect_sshd_bin
  systemctl list-unit-files --type=service --no-pager >/dev/null 2>&1 || die "systemctl 不可用（需要 systemd 环境）"
  detect_ssh_service
  [[ -f "${SSHD_MAIN}" ]] || die "未找到 SSH 主配置：${SSHD_MAIN}"
  if [[ ${DRY_RUN} -eq 0 ]]; then
    mkdir -p "${BACKUP_ROOT}"
    chmod 700 "${BACKUP_ROOT}"
    touch "${LOG_FILE}" 2>/dev/null || true
    chmod 600 "${LOG_FILE}" 2>/dev/null || true
  fi
}

acquire_lock() {
  command_exists flock || return 0
  [[ ${DRY_RUN} -eq 1 ]] && return 0
  exec 9>/run/vps-firstboot-hardening.lock
  flock -n 9 || die "已有 vps-firstboot-hardening 实例正在运行。"
}

validate_pubkey_line() {
  local key="$1" tmp
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
  if [[ ${DRY_RUN} -eq 1 ]]; then
    info "[dry-run] 将追加公钥到 /root/.ssh/authorized_keys"
    return 0
  fi
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  chown root:root /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  chown root:root /root/.ssh/authorized_keys
  if ! grep -qxF "${key}" /root/.ssh/authorized_keys; then
    printf '%s\n' "${key}" >> /root/.ssh/authorized_keys
    ok "已追加公钥到 /root/.ssh/authorized_keys"
  else
    info "公钥已存在于 authorized_keys，跳过。"
  fi
}

authorized_keys_has_valid_key() {
  local file="$1" line tmp
  [[ -f "${file}" ]] || return 1
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    tmp="$(mktemp)"
    printf '%s\n' "${line}" > "${tmp}"
    if ssh-keygen -l -f "${tmp}" >/dev/null 2>&1; then
      rm -f "${tmp}"
      return 0
    fi
    rm -f "${tmp}"
  done < "${file}"
  return 1
}

snapshot_ssh() {
  [[ ${DRY_RUN} -eq 1 ]] && { info "[dry-run] 将快照 /etc/ssh"; return 0; }
  SSH_SNAPSHOT_DIR="${BACKUP_ROOT}/ssh_${RUN_ID}"
  mkdir -p "${SSH_SNAPSHOT_DIR}"
  chmod 700 "${SSH_SNAPSHOT_DIR}"
  cp -a /etc/ssh/. "${SSH_SNAPSHOT_DIR}/"
  ok "已创建 SSH 回滚快照：${SSH_SNAPSHOT_DIR}"
}

normalize_sshd_dropin_include() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    info "[dry-run] 将把 Include /etc/ssh/sshd_config.d/*.conf 规范化到 sshd_config 前部"
    return 0
  fi
  backup_for_rollback "${SSHD_MAIN}"
  mkdir -p "${SSHD_DROPIN_DIR}"
  chmod 755 "${SSHD_DROPIN_DIR}"
  local tmp
  tmp="$(mktemp "${SSHD_MAIN}.tmp.XXXXXX")"
  awk -v script="${SCRIPT_NAME}" '
    BEGIN { inserted=0 }
    /^[[:space:]]*Include[[:space:]]+\/etc\/ssh\/sshd_config\.d\/\*\.conf([[:space:]]*#.*)?$/ { next }
    !inserted && $0 !~ /^[[:space:]]*(#|$)/ {
      print "# Added by " script
      print "Include /etc/ssh/sshd_config.d/*.conf"
      print ""
      inserted=1
    }
    { print }
    END {
      if (!inserted) {
        print "# Added by " script
        print "Include /etc/ssh/sshd_config.d/*.conf"
      }
    }
  ' "${SSHD_MAIN}" > "${tmp}"
  chmod 644 "${tmp}"
  mv "${tmp}" "${SSHD_MAIN}"
}

disable_global_port_lines() {
  [[ ${DRY_RUN} -eq 1 ]] && { info "[dry-run] 将注释 sshd_config 全局 Port 行，避免旧端口继续生效"; return 0; }
  backup_for_rollback "${SSHD_MAIN}"
  local tmp
  tmp="$(mktemp "${SSHD_MAIN}.tmp.XXXXXX")"
  awk '
    /^[[:space:]]*Match[[:space:]]/ { in_match=1 }
    !in_match && /^[[:space:]]*Port[[:space:]]+/ {
      print "# Disabled by vps-firstboot-hardening.sh: " $0
      next
    }
    { print }
  ' "${SSHD_MAIN}" > "${tmp}"
  chmod 644 "${tmp}"
  mv "${tmp}" "${SSHD_MAIN}"
}

port_in_use() {
  ss -lntH | awk '{print $4}' | grep -qE "[:.]$1$"
}

check_ssh_socket_for_port_change() {
  [[ ${SSH_SOCKET_ACTIVE} -eq 1 ]] || return 0
  if [[ ${DISABLE_SSH_SOCKET} -eq 1 ]]; then
    warn "检测到 ssh.socket active，将禁用 socket activation 以确保 sshd_config Port 生效。"
    run_or_dry systemctl disable --now ssh.socket
    SSH_SOCKET_ACTIVE=0
    return 0
  fi
  if [[ ${ASSUME_YES} -eq 0 ]]; then
    warn "检测到 ssh.socket active。若不禁用，SSH 端口可能仍由 socket ListenStream 控制。"
    if ask_yn_default_no "是否禁用 ssh.socket 并继续修改 SSH 端口？"; then
      run_or_dry systemctl disable --now ssh.socket
      SSH_SOCKET_ACTIVE=0
      return 0
    fi
  fi
  die "ssh.socket 当前 active。请加 --disable-ssh-socket，或先手动处理 socket activation。"
}

check_firewall_for_port_change() {
  local port="$1"
  if [[ ${UFW_ALLOW_SSH_PORT} -eq 1 ]]; then
    if command_exists ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
      run_or_dry ufw allow "${port}/tcp"
      ok "已通过 ufw 放行 ${port}/tcp。"
    else
      warn "未检测到 active ufw，跳过 ufw 放行。"
    fi
  fi
  if [[ ${ACK_FIREWALL_RISK} -eq 0 && ${UFW_ALLOW_SSH_PORT} -eq 0 ]]; then
    if [[ ${ASSUME_YES} -eq 1 ]]; then
      die "--yes 修改 SSH 端口时必须加 --ack-firewall-risk，或使用 --ufw-allow-ssh-port。"
    fi
    warn "脚本无法验证云安全组/外部防火墙。请确认已放行 ${port}/tcp。"
    ask_yn_default_yes "是否确认已处理防火墙并继续？" || die "用户取消 SSH 端口修改。"
  fi
}

prepare_ssh_port_config() {
  local port="$1"
  is_valid_port "${port}" || die "SSH 端口无效：${port}"
  check_ssh_socket_for_port_change
  check_firewall_for_port_change "${port}"
  if port_in_use "${port}"; then
    warn "检测到端口 ${port} 已有监听。"
    [[ ${ASSUME_YES} -eq 1 ]] || ask_yn_default_no "是否仍继续使用端口 ${port}？" || die "用户取消端口修改。"
  fi
  disable_global_port_lines
  write_file_atomic "${PORT_DROPIN}" 0644 "# Managed by ${SCRIPT_NAME}
Port ${port}
"
  ok "SSH 端口配置已写入：${PORT_DROPIN}"
}

setup_key_only_config() {
  local -a keys=()
  local line pubkey_input dry_run_generate=0

  if [[ -n "${PUBKEY_FILE}" ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
      line="${line%$'\r'}"
      [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
      keys+=("${line}")
    done < "${PUBKEY_FILE}"
    [[ ${#keys[@]} -gt 0 ]] || die "公钥文件为空或只有注释：${PUBKEY_FILE}"
  elif [[ -n "${PUBKEY_TEXT}" ]]; then
    keys+=("${PUBKEY_TEXT}")
  else
    if [[ ${ASSUME_YES} -eq 1 ]]; then
      die "--yes 非交互模式下启用仅密钥登录时，必须提供 --pubkey 或 --pubkey-file。"
    fi
    if [[ ${DRY_RUN} -eq 1 ]]; then
      info "[dry-run] 未提供公钥；实际交互运行时将提示粘贴公钥或回车生成临时私钥。"
      dry_run_generate=1
    else
      echo
      warn "为避免锁死，建议粘贴你本地已有 SSH 公钥。"
      warn "直接回车将由服务器生成 Ed25519 密钥，打印私钥供复制，并立即删除服务器端私钥。"
      echo
      read -r -p "$(echo -e "${BLUE}请输入 SSH 公钥，或直接回车自动生成: ${NC}")" pubkey_input || true
      [[ -n "${pubkey_input}" ]] && keys+=("${pubkey_input}")
    fi
  fi

  if [[ ${#keys[@]} -gt 0 ]]; then
    local key
    for key in "${keys[@]}"; do
      validate_pubkey_line "${key}" || die "检测到无效公钥：${key}"
      append_pubkey_if_missing "${key}"
    done
  else
    local generated_key="/root/.ssh/id_ed25519"
    if [[ ${DRY_RUN} -eq 1 && ${dry_run_generate} -eq 1 ]]; then
      info "[dry-run] 将生成 ${generated_key}，打印私钥后删除服务器端私钥，仅保留 .pub 和 authorized_keys。"
    else
    [[ -e "${generated_key}" || -e "${generated_key}.pub" ]] && die "${generated_key} 或 .pub 已存在；请先手动处理或提供公钥。"
    run_or_dry mkdir -p /root/.ssh
    run_or_dry chmod 700 /root/.ssh
    run_or_dry ssh-keygen -t ed25519 -a 64 -f "${generated_key}" -N "" -C "root@$(hostname)-$(date +%F)"
    run_or_dry chmod 600 "${generated_key}"
    run_or_dry chown root:root "${generated_key}" "${generated_key}.pub"
    if [[ ${DRY_RUN} -eq 0 ]]; then
      local gen_pub
      gen_pub="$(cat "${generated_key}.pub")"
      validate_pubkey_line "${gen_pub}" || die "自动生成公钥校验失败。"
      append_pubkey_if_missing "${gen_pub}"
      echo
      warn "================= 重要：请立刻保存下面这段【私钥】到你本地（文件权限 600） ================="
      cat "${generated_key}"
      warn "================= 私钥到此结束。请勿泄露。建议保存后立刻离线备份。 ================="
      echo
      rm -f "${generated_key}"
      ok "已删除服务器端私钥文件：${generated_key}；仅保留 ${generated_key}.pub 和 authorized_keys 中的公钥。"
    fi
    fi
  fi

  [[ ${DRY_RUN} -eq 1 ]] || authorized_keys_has_valid_key /root/.ssh/authorized_keys || die "authorized_keys 中未检测到有效 SSH 公钥。"

  local root_login="prohibit-password"
  [[ ${DISABLE_ROOT_LOGIN} -eq 1 ]] && root_login="no"
  write_file_atomic "${HARDEN_DROPIN}" 0644 "# Managed by ${SCRIPT_NAME} - key-only hardening
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
PermitRootLogin ${root_login}
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
"
  ok "SSH 仅密钥配置已写入：${HARDEN_DROPIN}"
}

create_sudo_user_if_requested() {
  [[ -n "${CREATE_USER}" ]] || return 0
  local user_home="/home/${CREATE_USER}"
  if ! id "${CREATE_USER}" >/dev/null 2>&1; then
    run_or_dry useradd -m -s /bin/bash "${CREATE_USER}"
    ok "已创建用户：${CREATE_USER}"
  else
    info "用户 ${CREATE_USER} 已存在，跳过创建。"
  fi
  if getent group sudo >/dev/null 2>&1; then
    run_or_dry usermod -aG sudo "${CREATE_USER}"
  elif getent group wheel >/dev/null 2>&1; then
    run_or_dry usermod -aG wheel "${CREATE_USER}"
  else
    warn "未找到 sudo/wheel 组，请手动授予 ${CREATE_USER} 管理权限。"
  fi
  [[ ${DRY_RUN} -eq 1 ]] && { info "[dry-run] 将复制 root authorized_keys 到 ${CREATE_USER}"; return 0; }
  authorized_keys_has_valid_key /root/.ssh/authorized_keys || die "root authorized_keys 无有效公钥，无法安全创建可登录用户。"
  mkdir -p "${user_home}/.ssh"
  cp -a /root/.ssh/authorized_keys "${user_home}/.ssh/authorized_keys"
  chown -R "${CREATE_USER}:${CREATE_USER}" "${user_home}/.ssh"
  chmod 700 "${user_home}/.ssh"
  chmod 600 "${user_home}/.ssh/authorized_keys"
  ok "已为 ${CREATE_USER} 配置 SSH 公钥登录。"
}

test_sshd() {
  "${SSHD_BIN}" -t
}

reload_sshd() {
  run_or_dry systemctl reload "${SSH_SERVICE}" || run_or_dry systemctl restart "${SSH_SERVICE}"
  [[ ${DRY_RUN} -eq 1 ]] || systemctl is-active --quiet "${SSH_SERVICE}"
  ok "SSH 服务已重载/重启：${SSH_SERVICE}"
}

sshd_t_value() {
  local key="$1"
  "${SSHD_BIN}" -T | awk -v k="${key}" '$1==k {print $2; exit}'
}

assert_ssh_state() {
  local run_port="$1" run_key="$2"
  [[ ${DRY_RUN} -eq 1 ]] && { info "[dry-run] 跳过最终 SSH 状态断言"; return 0; }
  local v ports root_login
  if [[ "${run_key}" -eq 1 ]]; then
    v="$(sshd_t_value passwordauthentication)"; [[ "${v}" == "no" ]] || die "断言失败：passwordauthentication=${v}"
    v="$(sshd_t_value kbdinteractiveauthentication)"; [[ "${v}" == "no" ]] || die "断言失败：kbdinteractiveauthentication=${v}"
    v="$(sshd_t_value permitemptypasswords)"; [[ "${v}" == "no" ]] || die "断言失败：permitemptypasswords=${v}"
    v="$(sshd_t_value pubkeyauthentication)"; [[ "${v}" == "yes" ]] || die "断言失败：pubkeyauthentication=${v}"
    root_login="prohibit-password"
    [[ ${DISABLE_ROOT_LOGIN} -eq 1 ]] && root_login="no"
    v="$(sshd_t_value permitrootlogin)"; [[ "${v}" == "${root_login}" ]] || die "断言失败：permitrootlogin=${v}"
  fi
  if [[ "${run_port}" -eq 1 ]]; then
    ports="$("${SSHD_BIN}" -T | awk '$1=="port"{print $2}')"
    echo "${ports}" | grep -qx "${SSH_PORT}" || die "断言失败：sshd -T 未包含端口 ${SSH_PORT}"
    if echo "${ports}" | grep -vx "${SSH_PORT}" | grep -q .; then
      die "断言失败：sshd -T 仍包含非目标端口：$(echo "${ports}" | tr '\n' ' ')"
    fi
    ss -lntH | awk -v port="${SSH_PORT}" '$4 ~ ("[:.]" port "$") {found=1} END {exit found?0:1}' || die "断言失败：未监听 ${SSH_PORT}/tcp"
  fi
  ok "SSH 最终状态断言通过。"
}

apply_ssh_stage() {
  local run_port="$1" run_key="$2"
  [[ "${run_port}" -eq 0 && "${run_key}" -eq 0 && -z "${CREATE_USER}" ]] && return 0
  start_stage "ssh"
  snapshot_ssh
  normalize_sshd_dropin_include
  [[ "${run_port}" -eq 1 ]] && prepare_ssh_port_config "${SSH_PORT}"
  [[ "${run_key}" -eq 1 ]] && setup_key_only_config
  create_sudo_user_if_requested
  test_sshd
  reload_sshd
  assert_ssh_state "${run_port}" "${run_key}"
  end_stage
}

disable_ipv6() {
  start_stage "ipv6"
  local conf="/etc/sysctl.d/99-disable-ipv6.conf"
  write_file_atomic "${conf}" 0644 "# Managed by ${SCRIPT_NAME}
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
"
  run_or_dry sysctl -p "${conf}"
  if [[ ${DRY_RUN} -eq 0 ]]; then
    [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == "1" ]] || die "IPv6 all.disable_ipv6 未生效"
    [[ "$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null)" == "1" ]] || die "IPv6 default.disable_ipv6 未生效"
    [[ "$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null)" == "1" ]] || die "IPv6 lo.disable_ipv6 未生效"
  fi
  end_stage
  ok "IPv6 sysctl 禁用已应用。"

  if resolve_step "${STEP_GRUB_IPV6}" "是否写入 GRUB 参数 ipv6.disable=1（需重启）？" "no"; then
    configure_grub_ipv6
  fi
}

configure_grub_ipv6() {
  start_stage "grub-ipv6"
  [[ -f /etc/default/grub ]] || die "未找到 /etc/default/grub；当前系统可能不是 GRUB 环境。"
  if ! command_exists update-grub && ! command_exists grub-mkconfig; then
    die "未找到 update-grub/grub-mkconfig，无法安全更新 GRUB。"
  fi
  backup_for_rollback /etc/default/grub
  if [[ ${DRY_RUN} -eq 1 ]]; then
    info "[dry-run] 将向 GRUB_CMDLINE_LINUX 添加 ipv6.disable=1"
    end_stage
    return 0
  fi
  if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub && ! grep -q '^GRUB_CMDLINE_LINUX="' /etc/default/grub; then
    die "GRUB_CMDLINE_LINUX 不是标准双引号格式，为避免误改请手动处理。"
  fi
  local tmp
  tmp="$(mktemp /etc/default/grub.tmp.XXXXXX)"
  awk '
    BEGIN { done=0 }
    /^GRUB_CMDLINE_LINUX="/ {
      if ($0 !~ /ipv6\.disable=1/) sub(/"$/, " ipv6.disable=1\"")
      done=1
    }
    { print }
    END { if (!done) print "GRUB_CMDLINE_LINUX=\"ipv6.disable=1\"" }
  ' /etc/default/grub > "${tmp}"
  chmod 644 "${tmp}"
  mv "${tmp}" /etc/default/grub
  grep -q 'ipv6.disable=1' /etc/default/grub || die "GRUB 参数写入校验失败"
  if command_exists update-grub; then
    update-grub
  else
    grub-mkconfig -o /boot/grub/grub.cfg
  fi
  end_stage
  ok "GRUB IPv6 禁用参数已写入；重启后生效。"
}

enable_bbr() {
  start_stage "bbr"
  if command_exists modprobe; then
    modprobe tcp_bbr >/dev/null 2>&1 || true
  fi
  local available
  available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
  if ! echo "${available}" | grep -qw bbr; then
    warn "当前内核未报告可用 BBR（available=${available:-N/A}），跳过写入 BBR 配置。"
    end_stage
    return 0
  fi
  local conf="/etc/sysctl.d/99-bbr.conf"
  write_file_atomic "${conf}" 0644 "# Managed by ${SCRIPT_NAME}
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
"
  run_or_dry sysctl -p "${conf}"
  if [[ ${DRY_RUN} -eq 0 ]]; then
    [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] || die "BBR 未生效"
  fi
  end_stage
  ok "BBR 已启用。"
}

audit_system() {
  echo "========== VPS Firstboot Hardening Audit =========="
  echo "Script: ${SCRIPT_NAME} v${SCRIPT_VERSION}"
  echo "OS: ${OS_PRETTY:-unknown}"
  echo "SSH service: ${SSH_SERVICE:-unknown}"
  echo "sshd: ${SSHD_BIN:-unknown}"
  echo
  echo "[sshd -T]"
  if [[ -n "${SSHD_BIN}" ]]; then
    "${SSHD_BIN}" -T 2>/dev/null | awk '
      $1=="port" ||
      $1=="pubkeyauthentication" ||
      $1=="passwordauthentication" ||
      $1=="kbdinteractiveauthentication" ||
      $1=="challengeresponseauthentication" ||
      $1=="permitemptypasswords" ||
      $1=="authenticationmethods" ||
      $1=="permitrootlogin" {print "  " $0}
    ' || true
  fi
  echo
  echo "[listening ports]"
  ss -lntH 2>/dev/null | awk '{print "  " $0}' || true
  echo
  echo "[sysctl]"
  local kv
  for kv in net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6 net.core.default_qdisc net.ipv4.tcp_congestion_control net.ipv4.tcp_available_congestion_control; do
    echo "  ${kv} = $(sysctl -n "${kv}" 2>/dev/null || echo N/A)"
  done
  echo
  echo "[firewall hints]"
  if command_exists ufw; then ufw status 2>/dev/null | sed 's/^/  /' || true; fi
  if command_exists nft; then echo "  nftables: available"; fi
  if command_exists iptables; then echo "  iptables: available"; fi
  echo "==================================================="
}

show_post_checks() {
  echo
  echo -e "${GREEN}====================== 执行后验收 ======================${NC}"
  audit_system
  echo -e "${GREEN}========================================================${NC}"
  echo
}

main() {
  parse_args "$@"
  need_root
  detect_os
  preflight_checks
  acquire_lock

  if [[ ${AUDIT_ONLY} -eq 1 ]]; then
    audit_system
    exit 0
  fi

  echo -e "${BLUE}==========================================================${NC}"
  echo -e "${BLUE}  VPS 安全初始化脚本 v${SCRIPT_VERSION}${NC}"
  echo -e "${BLUE}  兼容目标: Ubuntu 22/24, Debian 12/13${NC}"
  echo -e "${BLUE}==========================================================${NC}"
  [[ ${DRY_RUN} -eq 1 ]] && warn "当前为 dry-run，不会写入系统。"

  local run_ipv6=0 run_bbr=0 run_port=0 run_key=0
  if resolve_step "${STEP_IPV6}" "1) 是否禁用 IPv6？" "yes"; then run_ipv6=1; fi
  if resolve_step "${STEP_BBR}" "2) 是否开启 BBR？" "yes"; then run_bbr=1; fi
  if resolve_step "${STEP_PORT}" "3) 是否修改 SSH 端口？" "yes"; then run_port=1; fi
  if resolve_step "${STEP_KEYONLY}" "4) 是否配置 SSH Key 并强制仅密钥登录？" "yes"; then run_key=1; fi

  if [[ ${run_port} -eq 1 && ${PORT_SET_BY_ARG} -eq 0 ]]; then
    SSH_PORT="$(ask_input_default "请输入新的 SSH 端口" "${SSH_PORT}")"
    is_valid_port "${SSH_PORT}" || die "SSH 端口无效：${SSH_PORT}"
  fi

  [[ ${run_ipv6} -eq 1 ]] && disable_ipv6 || info "已跳过 IPv6 禁用。"
  [[ ${run_bbr} -eq 1 ]] && enable_bbr || info "已跳过 BBR 启用。"
  apply_ssh_stage "${run_port}" "${run_key}"

  show_post_checks
  ok "执行完成。不要断开当前会话，请先新开窗口验证 SSH 登录。"
}

main "$@"
