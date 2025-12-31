#!/bin/sh
# POSIX-compatible SSH 管理脚本（GitHub 公钥、密码/密钥登录控制、自动安装 fail2ban）
# 注意：脚本只处理公钥安装，绝对不处理私钥。本脚本需以 root 或具备相应权限的用户运行。

set -eu

cfg_sshd_config_path="/etc/ssh/sshd_config"
cfg_backup_dir="/var/backups/ssh-manager"
cfg_fail2ban_jail="/etc/fail2ban/jail.d/ssh-manager.local"

tmp_timestamp() {
  date +"%Y%m%dT%H%M%S"
}

log() {
  printf "%s\n" "$1"
}

error_exit() {
  printf "ERROR: %s\n" "$1" >&2
  exit 1
}

ensure_backup_dir() {
  if [ ! -d "$cfg_backup_dir" ]; then
    mkdir -p "$cfg_backup_dir"
  fi
}

backup_file() {
  src="$1"
  ensure_backup_dir
  ts=$(tmp_timestamp)
  dst="$cfg_backup_dir/$(basename "$src").$ts.bak"
  cp -p "$src" "$dst" || error_exit "备份 $src 失败"
  printf "%s" "$dst"
}

detect_init_system() {
  if command -v systemctl >/dev/null 2>&1; then
    printf "systemd"
  elif command -v service >/dev/null 2>&1; then
    printf "sysv"
  else
    printf "unknown"
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1; then
    printf "apt"
  elif command -v dnf >/dev/null 2>&1; then
    printf "dnf"
  elif command -v yum >/dev/null 2>&1; then
    printf "yum"
  elif command -v apk >/dev/null 2>&1; then
    printf "apk"
  elif command -v pacman >/dev/null 2>&1; then
    printf "pacman"
  elif command -v zypper >/dev/null 2>&1; then
    printf "zypper"
  else
    printf "unknown"
  fi
}

safe_reload_sshd() {
  # 验证 sshd 配置
  if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t >/dev/null 2>&1; then
      error_exit "sshd 配置验证失败，请检查配置"
    fi
  fi

  init_sys=$(detect_init_system)
  case "$init_sys" in
    systemd)
      systemctl reload sshd 2>/dev/null || systemctl restart sshd
      ;;
    sysv)
      service ssh reload 2>/dev/null || service sshd restart 2>/dev/null || service ssh restart
      ;;
    *)
      error_exit "无法识别 init 系统，手动重载 sshd"
      ;;
  esac
  log "sshd 已重载/重启（如果可用）。"
}

set_sshd_directive() {
  # 参数: 文件 指令 值 — 在整个文件中替换所有匹配项（保守）
  file="$1"
  key="$2"
  value="$3"
  if [ ! -f "$file" ]; then
    error_exit "配置文件 $file 不存在"
  fi
  if grep -E "^[[:space:]]*#?[[:space:]]*$key[[:space:]]+" "$file" >/dev/null 2>&1; then
    tmp=$(mktemp)
    awk -v k="$key" -v v="$value" '
      BEGIN{IGNORECASE=1}
      /^[[:space:]]*#/ { print; next }
      {
        if(tolower($1)==tolower(k)){
          print k " " v
        } else {
          print
        }
      }
    ' "$file" > "$tmp" && mv "$tmp" "$file"
  else
    printf "\n%s %s\n" "$key" "$value" >>"$file"
  fi
}

# 在全局段（first Match 之前）替换/追加指令，避免被后续 Match 覆盖
set_global_sshd_directive() {
  file="$1"
  key="$2"
  value="$3"

  if [ ! -f "$file" ]; then
    error_exit "配置文件 $file 不存在"
  fi

  head_tmp=$(mktemp)
  tail_tmp=$(mktemp)

  match_line=$(awk '/^Match[[:space:]]/ {print NR; exit}' "$file" 2>/dev/null || true)
  if [ -z "$match_line" ]; then
    head_end=$(wc -l <"$file" 2>/dev/null || echo 0)
  else
    head_end=$((match_line - 1))
  fi

  if [ "$head_end" -gt 0 ]; then
    sed -n "1,${head_end}p" "$file" > "$head_tmp"
    sed -n "$((head_end + 1)),\$p" "$file" > "$tail_tmp"
  else
    : >"$head_tmp"
    cat "$file" > "$tail_tmp"
  fi

  if grep -E "^[[:space:]]*#?[[:space:]]*$key[[:space:]]+" "$head_tmp" >/dev/null 2>&1; then
    awk -v k="$key" -v v="$value" '
      BEGIN{IGNORECASE=1}
      /^[[:space:]]*#/ { print; next }
      {
        if(tolower($1)==tolower(k)){
          print k " " v
        } else {
          print
        }
      }
    ' "$head_tmp" > "${head_tmp}.new" && mv "${head_tmp}.new" "$head_tmp"
  else
    printf "\n%s %s\n" "$key" "$value" >>"$head_tmp"
  fi

  cat "$head_tmp" "$tail_tmp" >"${file}.tmp" && mv "${file}.tmp" "$file"
  rm -f "$head_tmp" "$tail_tmp" 2>/dev/null || true
}

# 从 GitHub 获取用户公钥列表，输出到指定文件（out）
fetch_github_keys() {
  user="$1"
  out="$2"
  if [ -z "$user" ] || [ -z "$out" ]; then
    return 1
  fi
  url="https://github.com/${user}.keys"
  if command -v curl >/dev/null 2>&1; then
    if ! curl -fsS "$url" -o "$out" 2>/dev/null; then
      return 1
    fi
  elif command -v wget >/dev/null 2>&1; then
    if ! wget -q -O "$out" "$url" 2>/dev/null; then
      return 1
    fi
  else
    return 1
  fi
  if [ ! -s "$out" ]; then
    return 1
  fi
  if ! grep -E '^(ssh-|ecdsa-|sk-|ed25519-)' "$out" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

# 启用公钥认证（仅修改全局段配置）
enable_pubkey_authentication() {
  cfg_file="$1"
  backup_file "$cfg_file" >/dev/null
  set_global_sshd_directive "$cfg_file" "PubkeyAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "AuthorizedKeysFile" ".ssh/authorized_keys .ssh/authorized_keys2"
  log "已启用 PubkeyAuthentication"
}

# 检查是否启用了公钥或指定用户已有 authorized_keys
check_pubkey_enabled_or_keys_exist() {
  cfg_file="$1"
  user_home="$2"
  if grep -Ei '^[[:space:]]*PubkeyAuthentication[[:space:]]+yes' "$cfg_file" >/dev/null 2>&1; then
    return 0
  fi
  if [ -n "$user_home" ] && [ -f "$user_home/.ssh/authorized_keys" ] && [ -s "$user_home/.ssh/authorized_keys" ]; then
    return 0
  fi
  return 1
}

# 更严格的禁用密码登录：在全局段写入，避免 Match 覆盖
disable_password_authentication() {
  cfg_file="$1"
  backup_file "$cfg_file" >/dev/null

  set_global_sshd_directive "$cfg_file" "PubkeyAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "PasswordAuthentication" "no"
  set_global_sshd_directive "$cfg_file" "ChallengeResponseAuthentication" "no"
  # 不自动改 UsePAM，可能影响系统服务：若需改 PAM 由管理员决定
  set_global_sshd_directive "$cfg_file" "AuthenticationMethods" "publickey"
  set_global_sshd_directive "$cfg_file" "PermitRootLogin" "prohibit-password"

  log "已在全局段禁用密码相关认证，建议仅允许公钥认证"
}

# 启用密码登录（恢复为允许密码）
enable_password_authentication() {
  cfg_file="$1"
  backup_file "$cfg_file" >/dev/null

  set_global_sshd_directive "$cfg_file" "PasswordAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "ChallengeResponseAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "AuthenticationMethods" "any"
  set_global_sshd_directive "$cfg_file" "PermitRootLogin" "yes"

  log "已启用 PasswordAuthentication 并允许 root 基于密码登录"
}

set_ssh_port() {
  cfg_file="$1"
  port="$2"
  if ! printf "%s" "$port" | grep -E '^[0-9]+$' >/dev/null 2>&1; then
    error_exit "端口应为数字"
  fi
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] 2>/dev/null; then
    error_exit "端口超出范围 (1-65535)"
  fi
  backup_file "$cfg_file" >/dev/null
  set_sshd_directive "$cfg_file" "Port" "$port"
}

install_authorized_key() {
  pubkey_file="$1"
  user_home="$2"
  if [ -z "$user_home" ]; then
    error_exit "目标用户主目录不能为空"
  fi
  if [ ! -f "$pubkey_file" ]; then
    error_exit "公钥文件 $pubkey_file 不存在"
  fi
  ssh_dir="$user_home/.ssh"
  auth_file="$ssh_dir/authorized_keys"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$auth_file"
  chmod 600 "$auth_file"
  if ! grep -Fxf "$pubkey_file" "$auth_file" >/dev/null 2>&1; then
    cat "$pubkey_file" >>"$auth_file"
    log "已将公钥追加到 $auth_file"
  else
    log "公钥已存在于 $auth_file"
  fi
  if [ -f /etc/passwd ]; then
    owner=$(awk -F: -v dir="$user_home" '$6==dir{print $1; exit}' /etc/passwd || true)
    if [ -n "$owner" ]; then
      chown "$owner":"$owner" "$ssh_dir" "$auth_file" 2>/dev/null || true
    fi
  fi
}

ensure_root() {
  if [ "$(id -u)" != "0" ]; then
    error_exit "安装或修改系统服务需要以 root 用户运行"
  fi
}

install_fail2ban() {
  ensure_root
  mgr=$(detect_pkg_manager)
  log "检测到包管理器: $mgr"
  case "$mgr" in
    apt)
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 || true
      fi
      if ! apt-get install -y fail2ban >/dev/null 2>&1; then
        error_exit "apt: 安装 fail2ban 失败"
      fi
      ;;
    dnf)
      if ! dnf install -y fail2ban >/dev/null 2>&1; then
        dnf install -y epel-release >/dev/null 2>&1 || true
        dnf install -y fail2ban >/dev/null 2>&1 || error_exit "dnf: 安装 fail2ban 失败"
      fi
      ;;
    yum)
      if ! yum install -y fail2ban >/dev/null 2>&1; then
        yum install -y epel-release >/dev/null 2>&1 || true
        yum install -y fail2ban >/dev/null 2>&1 || error_exit "yum: 安装 fail2ban 失败"
      fi
      ;;
    apk)
      if ! apk add --no-progress --no-cache fail2ban >/dev/null 2>&1; then
        error_exit "apk: 安装 fail2ban 失败"
      fi
      ;;
    pacman)
      if ! pacman -Sy --noconfirm fail2ban >/dev/null 2>&1; then
        error_exit "pacman: 安装 fail2ban 失败"
      fi
      ;;
    zypper)
      if ! zypper -n install fail2ban >/dev/null 2>&1; then
        error_exit "zypper: 安装 fail2ban 失败"
      fi
      ;;
    *)
      error_exit "无法自动安装 fail2ban：未知包管理器"
      ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now fail2ban 2>/dev/null || systemctl start fail2ban 2>/dev/null || true
  else
    service fail2ban start 2>/dev/null || true
  fi

  if ! command -v fail2ban-server >/dev/null 2>&1; then
    error_exit "安装完成但未检测到 fail2ban-server 可执行文件"
  fi

  log "fail2ban 安装并启动（如适用）"
  return 0
}

configure_fail2ban() {
  if ! command -v fail2ban-server >/dev/null 2>&1; then
    log "未检测到 fail2ban，尝试自动安装..."
    if ! install_fail2ban; then
      log "自动安装 fail2ban 失败，跳过配置"
      return 1
    fi
  fi

  tmpfile=$(mktemp)
  cat >"$tmpfile" <<'EOF'
[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
maxretry = 5
EOF
  mkdir -p "$(dirname "$cfg_fail2ban_jail")"
  cp -p "$cfg_fail2ban_jail" "$cfg_fail2ban_jail".bak 2>/dev/null || true
  mv "$tmpfile" "$cfg_fail2ban_jail"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
  else
    service fail2ban restart 2>/dev/null || true
  fi
  log "fail2ban 配置已部署（并已尝试重载/重启服务）。"
}

print_usage() {
  cat <<EOF
用法：运行脚本将进入交互式主菜单（不再接受命令行参数）
EOF
}

interactive_menu() {
  if [ ! -t 0 ]; then
    error_exit "非交互式环境，请在终端中运行"
  fi

  default_port="22"
  if [ -f "$cfg_sshd_config_path" ]; then
    p=$(awk 'BEGIN{FS="[ \t]+"} /^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' "$cfg_sshd_config_path" 2>/dev/null || true)
    if [ -n "$p" ]; then
      default_port="$p"
    fi
  fi
  default_user_home="/root"
  default_github_user=${SUDO_USER:-$(whoami)}

  while :; do
    cat <<EOF

  请选择操作（输入对应编号；直接回车将返回菜单）:
  1) 从 GitHub 拉取并安装公钥；启用公钥登录（默认 GitHub 用户: ${default_github_user}, 目标主目录: ${default_user_home}）
  2) 设置 sshd 端口 (当前: ${default_port})
  3) 禁用密码登录（检测已启用公钥或目标用户已有公钥，否则拒绝）
  4) 安装并部署 fail2ban sshd jail
  5) 启用密码登录（并允许 root 密码登录）
  0) 退出
EOF
    printf "选择: "
    if ! read -r choice; then
      log "读取输入失败，退出"
      break
    fi
    if [ -z "$choice" ]; then
      log "未输入选择，返回菜单"
      continue
    fi

    case "$choice" in
      1)
        printf "GitHub 用户名（回车使用 %s）: " "$default_github_user"
        read -r gh_user || gh_user="$default_github_user"
        gh_user=${gh_user:-$default_github_user}
        printf "目标用户主目录（回车使用 %s）: " "$default_user_home"
        read -r user_home || user_home="$default_user_home"
        user_home=${user_home:-$default_user_home}
        tmp=$(mktemp)
        if fetch_github_keys "$gh_user" "$tmp"; then
          install_authorized_key "$tmp" "$user_home"
          enable_pubkey_authentication "$cfg_sshd_config_path"
          safe_reload_sshd
        else
          rm -f "$tmp" 2>/dev/null || true
          log "无法从 GitHub 获取公钥或无有效公钥，操作已取消"
        fi
        ;;
      2)
        printf "请输入新的 sshd 端口 (回车使用 %s): " "$default_port"
        read -r port || port="$default_port"
        port=${port:-$default_port}
        backup_file "$cfg_sshd_config_path" >/dev/null
        set_ssh_port "$cfg_sshd_config_path" "$port"
        safe_reload_sshd
        ;;
      3)
        printf "目标用户主目录（回车使用 %s）: " "$default_user_home"
        read -r user_home || user_home="$default_user_home"
        user_home=${user_home:-$default_user_home}
        if check_pubkey_enabled_or_keys_exist "$cfg_sshd_config_path" "$user_home"; then
          backup_file "$cfg_sshd_config_path" >/dev/null
          disable_password_authentication "$cfg_sshd_config_path"
          safe_reload_sshd
        else
          log "未检测到公钥认证或目标用户无公钥，拒绝禁用密码登录以避免被锁定"
        fi
        ;;
      4)
        configure_fail2ban
        ;;
      5)
        enable_password_authentication "$cfg_sshd_config_path"
        safe_reload_sshd
        ;;
      0)
        log "退出"
        break
        ;;
      *)
        log "无效选择: $choice"
        ;;
    esac
  done
}

main() {
  # 仅交互式主菜单 — 忽略任何命令行参数
  interactive_menu
  exit 0
}

main "$@"
