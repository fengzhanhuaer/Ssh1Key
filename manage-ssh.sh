#!/bin/sh
# POSIX-compatible SSH 管理脚本（GitHub 公钥、密码/密钥登录控制、自动安装 fail2ban）
# 注意：脚本只处理公钥安装，绝对不处理私钥。本脚本需以 root 或具备相应权限的用户运行。

set -eu

cfg_sshd_config_path="/etc/ssh/sshd_config"
cfg_backup_dir="/var/backups/ssh-manager"
cfg_fail2ban_jail="/etc/fail2ban/jail.d/ssh-manager.local"
cfg_sshd_port_override="/etc/ssh/sshd_config.d/99-ssh-manager-port.conf"
cfg_default_github_user="fengzhanhuaer"
cfg_os_id="unknown"
cfg_os_like=""
cfg_os_version_id=""
cfg_os_major_version=""

read_os_release_value() {
  key="$1"
  if [ ! -r /etc/os-release ]; then
    return 0
  fi

  awk -v k="$key" '
    $0 ~ "^[[:space:]]*" k "=" {
      line = $0
      sub(/^[^=]*=/, "", line)
      if (line ~ /^"/) {
        sub(/^"/, "", line)
        sub(/"$/, "", line)
      }
      print line
      exit
    }
  ' /etc/os-release 2>/dev/null || true
}

load_os_release_info() {
  cfg_os_id=$(read_os_release_value "ID")
  cfg_os_like=$(read_os_release_value "ID_LIKE")
  cfg_os_version_id=$(read_os_release_value "VERSION_ID")

  if [ -z "$cfg_os_id" ]; then
    cfg_os_id="unknown"
  fi

  cfg_os_major_version=$(printf "%s" "$cfg_os_version_id" | awk -F. 'NR==1 {print $1}')
}

is_debian_family() {
  case " $cfg_os_id $cfg_os_like " in
    *" debian "*|*" ubuntu "*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_rhel_family() {
  case " $cfg_os_id $cfg_os_like " in
    *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*|*" ol "*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_debian_13_or_newer() {
  if ! is_debian_family; then
    return 1
  fi

  if ! printf "%s" "$cfg_os_major_version" | grep -E '^[0-9]+$' >/dev/null 2>&1; then
    return 1
  fi

  if [ "$cfg_os_major_version" -ge 13 ] 2>/dev/null; then
    return 0
  fi

  return 1
}

normalize_home_path() {
  raw_home="$1"
  if [ -z "$raw_home" ]; then
    printf ""
    return 0
  fi

  normalized_home=$(printf "%s" "$raw_home" | sed 's#/*$##')
  if [ -z "$normalized_home" ]; then
    normalized_home="/"
  fi

  printf "%s" "$normalized_home"
}

resolve_default_login_user() {
  if [ -n "${SUDO_USER:-}" ]; then
    printf "%s" "$SUDO_USER"
    return 0
  fi
  whoami
}

resolve_default_github_user() {
  if [ -n "$cfg_default_github_user" ]; then
    printf "%s" "$cfg_default_github_user"
    return 0
  fi

  resolve_default_login_user
}

resolve_user_home_by_name() {
  user_name="$1"

  if [ -z "$user_name" ]; then
    return 1
  fi

  if command -v getent >/dev/null 2>&1; then
    getent passwd "$user_name" 2>/dev/null | awk -F: 'NR==1 {print $6}'
    return 0
  fi

  if [ -f /etc/passwd ]; then
    awk -F: -v u="$user_name" '$1==u {print $6; exit}' /etc/passwd 2>/dev/null || true
    return 0
  fi

  return 1
}

resolve_user_by_home() {
  target_home=$(normalize_home_path "$1")

  if [ -z "$target_home" ]; then
    return 1
  fi

  if command -v getent >/dev/null 2>&1; then
    getent passwd 2>/dev/null | awk -F: -v dir="$target_home" '
      function norm(path) {
        sub(/\/+$/, "", path)
        if (path == "") {
          path = "/"
        }
        return path
      }
      norm($6) == dir {print $1; exit}
    '
    return 0
  fi

  if [ -f /etc/passwd ]; then
    awk -F: -v dir="$target_home" '
      function norm(path) {
        sub(/\/+$/, "", path)
        if (path == "") {
          path = "/"
        }
        return path
      }
      norm($6) == dir {print $1; exit}
    ' /etc/passwd 2>/dev/null || true
    return 0
  fi

  return 1
}

resolve_default_target_home() {
  default_user=$(resolve_default_login_user)
  resolved_home=$(resolve_user_home_by_name "$default_user" 2>/dev/null || true)

  if [ -n "$resolved_home" ]; then
    printf "%s" "$(normalize_home_path "$resolved_home")"
    return 0
  fi

  if [ "$default_user" = "root" ]; then
    printf "/root"
  else
    printf "/home/%s" "$default_user"
  fi
}

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

write_or_append_sshd_directive() {
  file="$1"
  key="$2"
  value="$3"

  tmp=$(mktemp)
  if ! awk -v k="$key" -v v="$value" '
    BEGIN {
      IGNORECASE = 1
      replaced = 0
    }
    /^[[:space:]]*#/ {
      print
      next
    }
    {
      if (tolower($1) == tolower(k)) {
        print k " " v
        replaced = 1
      } else {
        print
      }
    }
    END {
      if (!replaced) {
        print k " " v
      }
    }
  ' "$file" >"$tmp"; then
    rm -f "$tmp" 2>/dev/null || true
    error_exit "更新 sshd 指令失败: $key"
  fi
  mv "$tmp" "$file"
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

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl reload sshd 2>/dev/null ||
      systemctl reload ssh 2>/dev/null ||
      systemctl restart sshd 2>/dev/null ||
      systemctl restart ssh 2>/dev/null; then
      log "sshd 已重载/重启（systemd）。"
      return 0
    fi
  fi

  if command -v service >/dev/null 2>&1; then
    if service ssh reload 2>/dev/null ||
      service sshd reload 2>/dev/null ||
      service ssh restart 2>/dev/null ||
      service sshd restart 2>/dev/null; then
      log "sshd 已重载/重启（service）。"
      return 0
    fi
  fi

  error_exit "无法自动重载/重启 sshd，请手动执行"
}

set_sshd_directive() {
  # 参数: 文件 指令 值 — 在整个文件中替换所有匹配项（保守）
  file="$1"
  key="$2"
  value="$3"
  if [ ! -f "$file" ]; then
    error_exit "配置文件 $file 不存在"
  fi
  write_or_append_sshd_directive "$file" "$key" "$value"
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
  merged_tmp=$(mktemp)

  match_line=$(awk '/^[[:space:]]*Match[[:space:]]+/ {print NR; exit}' "$file" 2>/dev/null || true)
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

  write_or_append_sshd_directive "$head_tmp" "$key" "$value"

  cat "$head_tmp" "$tail_tmp" >"$merged_tmp"
  mv "$merged_tmp" "$file"
  rm -f "$head_tmp" "$tail_tmp" "$merged_tmp" 2>/dev/null || true
}

# 从 GitHub 获取用户公钥列表，输出到指定文件（out）
fetch_github_keys() {
  user="$1"
  out="$2"
  if [ -z "$user" ] || [ -z "$out" ]; then
    return 1
  fi
  # GitHub username 基本格式校验，避免无效请求
  if ! printf "%s" "$user" | grep -E '^[A-Za-z0-9][A-Za-z0-9-]*$' >/dev/null 2>&1; then
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

# 确保单个文件中 PubkeyAuthentication 为 yes（用于 Include 文件修复）
apply_pubkey_enable_to_file() {
  file="$1"
  if [ ! -f "$file" ]; then
    return 0
  fi
  # 只处理含有 PubkeyAuthentication 指令（含注释关闭）的文件
  if ! grep -Eiq '^[[:space:]]*#?[[:space:]]*PubkeyAuthentication[[:space:]]+' "$file"; then
    return 0
  fi
  backup_file "$file" >/dev/null
  set_sshd_directive "$file" "PubkeyAuthentication" "yes"
  log "已更新 $file 中的 PubkeyAuthentication 为 yes"
}

# 处理所有 Include 引入的文件，确保 PubkeyAuthentication yes
process_included_configs_for_pubkey() {
  cfg_file="$1"

  # 处理 sshd_config.d/ 标准目录
  config_dir="/etc/ssh/sshd_config.d"
  if [ -d "$config_dir" ]; then
    for file in "$config_dir"/*.conf; do
      if [ -f "$file" ]; then
        apply_pubkey_enable_to_file "$file"
      fi
    done
  fi

  # 处理主配置中 Include 指令引用的其他文件
  awk '
    BEGIN { IGNORECASE = 1 }
    /^[[:space:]]*#/ { next }
    tolower($1) == "include" {
      for (i = 2; i <= NF; i++) { print $i }
    }
  ' "$cfg_file" | while IFS= read -r include_pattern; do
    [ -z "$include_pattern" ] && continue
    case "$include_pattern" in
      /*) abs_pattern="$include_pattern" ;;
      *)  abs_pattern="/etc/ssh/$include_pattern" ;;
    esac
    for included_file in $abs_pattern; do
      if [ -f "$included_file" ] && [ "$included_file" != "$cfg_file" ]; then
        apply_pubkey_enable_to_file "$included_file"
      fi
    done
  done
}

# 启用公钥认证
enable_pubkey_authentication() {
  cfg_file="$1"
  backup_file "$cfg_file" >/dev/null
  # 先修复所有 Include 文件（Include 在主配置顶部时优先级更高）
  process_included_configs_for_pubkey "$cfg_file"
  # 再写主配置全局段
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

check_pubkey_auth_enabled_for_user() {
  user="$1"

  if ! command -v sshd >/dev/null 2>&1; then
    return 0
  fi

  if [ -n "$user" ]; then
    effective_cfg=$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null || true)
  else
    effective_cfg=$(sshd -T 2>/dev/null || true)
  fi

  if [ -z "$effective_cfg" ]; then
    return 0
  fi

  pa=$(printf "%s\n" "$effective_cfg" | awk '$1=="pubkeyauthentication"{print $2; exit}')
  akf=$(printf "%s\n" "$effective_cfg" | awk '$1=="authorizedkeysfile"{print $2; exit}')

  case "$pa" in
    yes|unbound|host-bound)
      pa_enabled=1
      ;;
    *)
      pa_enabled=0
      ;;
  esac

  if [ -n "$akf" ] && [ "$akf" != "none" ]; then
    akf_enabled=1
  else
    akf_enabled=0
  fi

  if [ "$pa_enabled" -eq 1 ] && [ "$akf_enabled" -eq 1 ]; then
    return 0
  fi

  if [ -n "$user" ]; then
    log "警告: 用户 $user 生效配置 pubkeyauthentication=${pa:-<empty>} authorizedkeysfile=${akf:-<empty>}"
  else
    log "警告: 默认生效配置 pubkeyauthentication=${pa:-<empty>} authorizedkeysfile=${akf:-<empty>}"
  fi

  return 1
}

verify_pubkey_authentication_enabled() {
  target_user="$1"

  if ! command -v sshd >/dev/null 2>&1; then
    log "警告: 未找到 sshd 命令，跳过公钥认证生效校验"
    return 0
  fi

  default_ok=0
  target_ok=0

  if check_pubkey_auth_enabled_for_user ""; then
    default_ok=1
  fi

  if [ -n "$target_user" ]; then
    if check_pubkey_auth_enabled_for_user "$target_user"; then
      target_ok=1
    fi

    if [ "$target_ok" -ne 1 ]; then
      log "警告: 用户 $target_user 上下文下 PubkeyAuthentication 未启用"
      return 1
    fi

    if [ "$default_ok" -ne 1 ]; then
      log "提示: 默认上下文未启用公钥，但目标用户上下文已启用（可能由 Match 规则导致）"
    fi

    log "已确认目标用户 $target_user 的公钥认证为启用状态"
    return 0
  fi

  if [ "$default_ok" -ne 1 ]; then
    log "警告: 默认上下文下 PubkeyAuthentication 未启用"
    return 1
  fi

  log "已确认公钥认证在默认上下文中为启用状态"
  return 0
}

# 获取 sshd 实际生效端口（逗号分隔）。优先 sshd -T，其次回退到主配置文件。
get_effective_sshd_ports() {
  ports=""

  if command -v sshd >/dev/null 2>&1; then
    ports=$(sshd -T 2>/dev/null | awk '
      BEGIN {
        out = ""
      }
      tolower($1) == "port" && $2 ~ /^[0-9]+$/ {
        if (!seen[$2]++) {
          if (out == "") {
            out = $2
          } else {
            out = out "," $2
          }
        }
      }
      END {
        print out
      }
    ')
  fi

  if [ -n "$ports" ]; then
    printf "%s" "$ports"
    return 0
  fi

  if [ -f "$cfg_sshd_config_path" ]; then
    ports=$(awk '
      BEGIN {
        IGNORECASE = 1
        out = ""
      }
      /^[[:space:]]*#/ { next }
      tolower($1) == "port" && $2 ~ /^[0-9]+$/ {
        if (!seen[$2]++) {
          if (out == "") {
            out = $2
          } else {
            out = out "," $2
          }
        }
      }
      END {
        print out
      }
    ' "$cfg_sshd_config_path" 2>/dev/null || true)
  fi

  if [ -n "$ports" ]; then
    printf "%s" "$ports"
  else
    printf "22"
  fi
}

port_list_contains() {
  port_list="$1"
  target_port="$2"
  case ",$port_list," in
    *,"$target_port",*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_sshd_port_override_file() {
  port="$1"
  config_dir=$(dirname "$cfg_sshd_port_override")

  if [ ! -d "$config_dir" ]; then
    return 0
  fi

  if [ -f "$cfg_sshd_port_override" ]; then
    backup_file "$cfg_sshd_port_override" >/dev/null
  fi

  tmp=$(mktemp)
  cat >"$tmp" <<EOF
# Managed by ssh-manager. Keep this file last to avoid port override surprises.
Port $port
EOF
  mv "$tmp" "$cfg_sshd_port_override"

  # 将主配置及其他 include 文件中的 Port 指令注释掉，避免多端口累加
  # （OpenSSH 的 Port 是累加而非覆盖，必须只保留一个来源）
  _remove_port_from_file() {
    _file="$1"
    if [ ! -f "$_file" ]; then return 0; fi
    # 跳过我们自己管理的 override 文件
    [ "$_file" = "$cfg_sshd_port_override" ] && return 0
    if grep -Eq '^[[:space:]]*Port[[:space:]]+[0-9]+' "$_file" 2>/dev/null; then
      backup_file "$_file" >/dev/null
      sed -i 's/^[[:space:]]*Port[[:space:]]\+[0-9]\+/# & (commented by ssh-manager, see sshd_config.d\/99-ssh-manager-port.conf)/' "$_file"
      log "已注释 $_file 中的 Port 指令（由 override 文件统一管理）"
    fi
  }

  _remove_port_from_file "$cfg_sshd_config_path"

  for _f in "$config_dir"/*.conf; do
    [ -f "$_f" ] && _remove_port_from_file "$_f"
  done
}

verify_ssh_port_effective() {
  expected_port="$1"
  actual_ports=$(get_effective_sshd_ports)

  if port_list_contains "$actual_ports" "$expected_port"; then
    log "sshd 生效端口: $actual_ports"
    return 0
  fi

  log "警告: 目标端口 $expected_port 未生效，当前生效端口: $actual_ports"
  return 1
}

diagnose_socket_activation_port_issue() {
  active_sockets=""
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active ssh.socket >/dev/null 2>&1; then
      active_sockets="$active_sockets ssh.socket"
    fi
    if systemctl is-active sshd.socket >/dev/null 2>&1; then
      active_sockets="$active_sockets sshd.socket"
    fi
  fi

  if [ -n "$active_sockets" ]; then
    log "提示: 检测到 systemd socket 激活:$active_sockets"
    log "提示: socket 模式下监听端口可能由 *.socket 的 ListenStream 控制，而非 sshd_config 的 Port。"
  fi
}

ensure_selinux_ssh_port_context() {
  port="$1"

  if [ "$port" = "22" ]; then
    return 0
  fi

  if ! command -v getenforce >/dev/null 2>&1; then
    return 0
  fi

  selinux_mode=$(getenforce 2>/dev/null || echo "Disabled")
  case "$selinux_mode" in
    Disabled|disabled)
      return 0
      ;;
  esac

  selinux_enforcing=0
  case "$selinux_mode" in
    Enforcing|enforcing)
      selinux_enforcing=1
      ;;
  esac

  if ! command -v semanage >/dev/null 2>&1; then
    log "警告: SELinux=$selinux_mode 但未找到 semanage，请手动执行: semanage port -a -t ssh_port_t -p tcp $port"
    if [ "$selinux_enforcing" -eq 1 ]; then
      return 1
    fi
    return 0
  fi

  if semanage port -a -t ssh_port_t -p tcp "$port" >/dev/null 2>&1; then
    log "已为 SELinux 添加 ssh_port_t tcp/$port"
    return 0
  fi

  if semanage port -m -t ssh_port_t -p tcp "$port" >/dev/null 2>&1; then
    log "已为 SELinux 更新 ssh_port_t tcp/$port"
    return 0
  fi

  if semanage port -l 2>/dev/null | awk -v p="$port" '
    $1 == "ssh_port_t" && $2 == "tcp" {
      ports = ""
      for (i = 3; i <= NF; i++) {
        if (ports == "") {
          ports = $i
        } else {
          ports = ports " " $i
        }
      }

      gsub(/,/, " ", ports)
      n = split(ports, arr, /[[:space:]]+/)
      for (j = 1; j <= n; j++) {
        token = arr[j]
        if (token == "") {
          continue
        }

        if (index(token, "-") > 0) {
          split(token, range, "-")
          if (range[1] ~ /^[0-9]+$/ && range[2] ~ /^[0-9]+$/ && p >= range[1] && p <= range[2]) {
            found = 1
          }
        } else if (token == p) {
          found = 1
        }
      }
    }
    END {
      exit(found ? 0 : 1)
    }
  '; then
    log "SELinux 已存在 ssh_port_t tcp/$port"
    return 0
  fi

  log "警告: 更新 SELinux 端口策略失败，可能导致 sshd 无法监听 $port"
  if [ "$selinux_enforcing" -eq 1 ]; then
    return 1
  fi

  return 0
}

ensure_port_allowed_by_ufw() {
  port="$1"

  if ! command -v ufw >/dev/null 2>&1; then
    return 2
  fi

  ufw_status=$(ufw status 2>/dev/null | awk 'NR==1 && $1=="Status:" {print tolower($2)}')
  if [ "$ufw_status" != "active" ]; then
    return 2
  fi

  if ufw allow "$port/tcp" >/dev/null 2>&1; then
    log "已通过 UFW 放行 $port/tcp"
    return 0
  fi

  log "警告: UFW 处于 active，但自动放行 $port/tcp 失败，请手动执行: ufw allow $port/tcp"
  return 1
}

ensure_port_allowed_by_firewalld() {
  port="$1"

  if ! command -v firewall-cmd >/dev/null 2>&1; then
    return 2
  fi

  if ! firewall-cmd --state >/dev/null 2>&1; then
    return 2
  fi

  if firewall-cmd --quiet --query-port="$port/tcp" >/dev/null 2>&1; then
    log "firewalld 已放行 $port/tcp"
    return 0
  fi

  runtime_ok=0
  permanent_ok=0

  if firewall-cmd --quiet --add-port="$port/tcp" >/dev/null 2>&1; then
    runtime_ok=1
  fi

  if firewall-cmd --quiet --permanent --add-port="$port/tcp" >/dev/null 2>&1; then
    permanent_ok=1
  fi

  if [ "$runtime_ok" -eq 1 ] || [ "$permanent_ok" -eq 1 ]; then
    if [ "$permanent_ok" -eq 1 ]; then
      firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    log "已通过 firewalld 放行 $port/tcp"
    return 0
  fi

  log "警告: firewalld 处于 running，但自动放行 $port/tcp 失败"
  return 1
}

ensure_firewall_port_open() {
  port="$1"

  if ensure_port_allowed_by_ufw "$port"; then
    return 0
  else
    rc=$?
    if [ "$rc" -ne 2 ]; then
      return 1
    fi
  fi

  if ensure_port_allowed_by_firewalld "$port"; then
    return 0
  else
    rc=$?
    if [ "$rc" -ne 2 ]; then
      return 1
    fi
  fi

  if is_debian_family || is_rhel_family; then
    log "提示: 未检测到 active 的 UFW/firewalld；若使用了其他防火墙，请手动放行 tcp/$port"
  fi

  return 0
}

is_tcp_port_listening() {
  port="$1"

  if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | awk -v p="$port" '
      NR == 1 && $1 == "State" { next }
      {
        addr = $4
        gsub(/\[/, "", addr)
        gsub(/\]/, "", addr)
        n = split(addr, parts, ":")
        local_port = parts[n]
        if (local_port == p) {
          found = 1
        }
      }
      END {
        exit(found ? 0 : 1)
      }
    '; then
      return 0
    fi
  fi

  if command -v netstat >/dev/null 2>&1; then
    if netstat -ltn 2>/dev/null | awk -v p="$port" '
      NR <= 2 { next }
      {
        addr = $4
        gsub(/\[/, "", addr)
        gsub(/\]/, "", addr)
        n = split(addr, parts, ":")
        local_port = parts[n]
        if (local_port == p) {
          found = 1
        }
      }
      END {
        exit(found ? 0 : 1)
      }
    '; then
      return 0
    fi
  fi

  return 1
}

wait_for_sshd_port_listener() {
  port="$1"
  retries=6

  while [ "$retries" -gt 0 ]; do
    if is_tcp_port_listening "$port"; then
      log "检测到 sshd 正在监听端口 $port"
      return 0
    fi
    retries=$((retries - 1))
    sleep 1
  done

  log "警告: 在预期时间内未检测到 sshd 监听端口 $port"
  return 1
}

check_password_auth_disabled_for_user() {
  user="$1"

  if ! command -v sshd >/dev/null 2>&1; then
    return 0
  fi

  if [ -n "$user" ]; then
    effective_cfg=$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null || true)
  else
    effective_cfg=$(sshd -T 2>/dev/null || true)
  fi

  if [ -z "$effective_cfg" ]; then
    return 0
  fi

  pa=$(printf "%s\n" "$effective_cfg" | awk '$1=="passwordauthentication"{print $2; exit}')
  kia=$(printf "%s\n" "$effective_cfg" | awk '$1=="kbdinteractiveauthentication"{print $2; exit}')
  cra=$(printf "%s\n" "$effective_cfg" | awk '$1=="challengeresponseauthentication"{print $2; exit}')

  if [ "$pa" = "yes" ] || [ "$kia" = "yes" ] || [ "$cra" = "yes" ]; then
    return 1
  fi
  return 0
}

verify_password_authentication_disabled() {
  if ! command -v sshd >/dev/null 2>&1; then
    log "警告: 未找到 sshd 命令，跳过密码认证生效校验"
    return 0
  fi

  if ! check_password_auth_disabled_for_user ""; then
    log "警告: 默认上下文下仍检测到密码相关认证为启用"
    return 1
  fi

  if [ -f /etc/passwd ] && grep -E '^root:' /etc/passwd >/dev/null 2>&1; then
    if ! check_password_auth_disabled_for_user "root"; then
      log "警告: root 上下文下仍检测到密码相关认证为启用"
      return 1
    fi
  fi

  if [ -n "${SUDO_USER:-}" ]; then
    if ! check_password_auth_disabled_for_user "$SUDO_USER"; then
      log "警告: 用户 $SUDO_USER 上下文下仍检测到密码相关认证为启用"
      return 1
    fi
  fi

  log "已确认密码相关认证在已检查上下文中为禁用状态"
  return 0
}
# 验证 sshd 配置是否正确应用
verify_sshd_config() {
  cfg_file="$1"
  
  log "正在验证 sshd 配置..."
  
  # 使用 sshd -T 检查实际生效的配置
  if command -v sshd >/dev/null 2>&1; then
    if ! actual_config=$(sshd -T 2>/dev/null); then
      log "警告: sshd -T 执行失败，跳过生效配置检查"
      return 0
    fi
    
    # 检查关键配置项
    if echo "$actual_config" | grep -i "passwordauthentication yes" >/dev/null 2>&1; then
      log "警告: PasswordAuthentication 仍为 yes，可能被 Match 块或其他配置文件覆盖"
    fi
    
    if echo "$actual_config" | grep -i "permitrootlogin yes" >/dev/null 2>&1; then
      log "警告: PermitRootLogin 仍为 yes，可能被 Match 块或其他配置文件覆盖"
    fi
    
    if echo "$actual_config" | grep -i "kbdinteractiveauthentication yes" >/dev/null 2>&1; then
      log "警告: KbdInteractiveAuthentication 仍为 yes，可能被 Match 块或其他配置文件覆盖"
    fi
  else
    log "警告: 无法找到 sshd 命令，跳过配置验证"
  fi
}

# 处理 sshd_config.d 目录中的配置文件
apply_password_disable_policy_to_file() {
  file="$1"
  if [ ! -f "$file" ]; then
    return 0
  fi

  if ! grep -Eiq '^[[:space:]]*#?[[:space:]]*(PasswordAuthentication|PermitRootLogin|ChallengeResponseAuthentication|KbdInteractiveAuthentication|UsePAM)[[:space:]]+' "$file"; then
    return 0
  fi

  backup_file "$file" >/dev/null
  set_sshd_directive "$file" "PasswordAuthentication" "no"
  set_sshd_directive "$file" "PermitRootLogin" "prohibit-password"
  set_sshd_directive "$file" "ChallengeResponseAuthentication" "no"
  set_sshd_directive "$file" "KbdInteractiveAuthentication" "no"
  set_sshd_directive "$file" "UsePAM" "yes"

  log "已更新 $file 中的密码认证设置"
}

process_sshd_config_d() {
  config_dir="/etc/ssh/sshd_config.d"
  
  if [ -d "$config_dir" ]; then
    log "检查 $config_dir 目录中的配置文件..."
    
    for file in "$config_dir"/*.conf; do
      if [ -f "$file" ]; then
        apply_password_disable_policy_to_file "$file"
      fi
    done
  fi
}

process_sshd_included_configs() {
  cfg_file="$1"
  if [ ! -f "$cfg_file" ]; then
    return 0
  fi

  awk '
    BEGIN { IGNORECASE = 1 }
    /^[[:space:]]*#/ { next }
    tolower($1) == "include" {
      for (i = 2; i <= NF; i++) {
        print $i
      }
    }
  ' "$cfg_file" | while IFS= read -r include_pattern; do
    if [ -z "$include_pattern" ]; then
      continue
    fi

    case "$include_pattern" in
      /*)
        abs_pattern="$include_pattern"
        ;;
      *)
        abs_pattern="/etc/ssh/$include_pattern"
        ;;
    esac

    for included_file in $abs_pattern; do
      if [ -f "$included_file" ] && [ "$included_file" != "$cfg_file" ]; then
        apply_password_disable_policy_to_file "$included_file"
      fi
    done
  done
}

# 禁用密码登录
disable_password_authentication() {
  cfg_file="$1"
  backup_file "$cfg_file" >/dev/null
  
  # 先修复所有 Include 文件中的 PubkeyAuthentication（Include 位于顶部时优先级更高）
  process_included_configs_for_pubkey "$cfg_file"

  # 再写主配置全局指令
  set_global_sshd_directive "$cfg_file" "PubkeyAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "PasswordAuthentication" "no"
  set_global_sshd_directive "$cfg_file" "ChallengeResponseAuthentication" "no"
  set_global_sshd_directive "$cfg_file" "KbdInteractiveAuthentication" "no"
  set_global_sshd_directive "$cfg_file" "UsePAM" "yes"
  set_global_sshd_directive "$cfg_file" "PermitRootLogin" "prohibit-password"

  # 再覆盖主配置中所有上下文（含 Match）里的同名指令，避免局部放开
  # 注意：PubkeyAuthentication 仅在全局段设置，不覆盖 Match 块（避免误关闭）
  set_sshd_directive "$cfg_file" "PasswordAuthentication" "no"
  set_sshd_directive "$cfg_file" "ChallengeResponseAuthentication" "no"
  set_sshd_directive "$cfg_file" "KbdInteractiveAuthentication" "no"
  set_sshd_directive "$cfg_file" "UsePAM" "yes"
  set_sshd_directive "$cfg_file" "PermitRootLogin" "prohibit-password"
  
  # 处理主配置中 Include 引入的文件（兼容自定义目录）
  process_sshd_included_configs "$cfg_file"

  # 处理配置目录中的文件
  process_sshd_config_d
  
  # 验证配置是否正确应用
  # 直接调用函数，不使用 command -v 检查，因为我们知道它存在
  verify_sshd_config "$cfg_file"
  
  log "已禁用密码登录相关的所有认证方式"
}

# 启用密码登录（恢复为允许密码）
enable_password_authentication() {
  cfg_file="$1"
  backup_file "$cfg_file" >/dev/null

  set_global_sshd_directive "$cfg_file" "PasswordAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "ChallengeResponseAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "KbdInteractiveAuthentication" "yes"
  set_global_sshd_directive "$cfg_file" "UsePAM" "yes"
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
  set_global_sshd_directive "$cfg_file" "Port" "$port"
  ensure_sshd_port_override_file "$port"
}

install_authorized_key() {
  pubkey_file="$1"
  user_home=$(normalize_home_path "$2")
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

  valid_count=0
  add_count=0
  rsa_count=0
  modern_count=0
  while IFS= read -r key_line || [ -n "$key_line" ]; do
    # 去除可能存在的 Windows 回车符 (\r) 和空白字符，防止 sshd 解析出错（特别是没有 comment 的 key）
    key_line=$(printf "%s" "$key_line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # 跳过空行和注释行
    case "$key_line" in
      "" | \#*)
        continue
        ;;
    esac

    # 仅接受常见 SSH 公钥前缀
    if ! printf "%s" "$key_line" | grep -E '^(ssh-|ecdsa-|sk-|ed25519-)' >/dev/null 2>&1; then
      continue
    fi

    key_type=$(printf "%s" "$key_line" | awk '{print $1}')
    case "$key_type" in
      ssh-rsa)
        rsa_count=$((rsa_count + 1))
        ;;
      ssh-ed25519|ecdsa-*|sk-*)
        modern_count=$((modern_count + 1))
        ;;
    esac

    valid_count=$((valid_count + 1))

    if ! grep -Fqx "$key_line" "$auth_file" >/dev/null 2>&1; then
      printf "%s\n" "$key_line" >>"$auth_file"
      add_count=$((add_count + 1))
    fi
  done <"$pubkey_file"

  if [ "$valid_count" -eq 0 ]; then
    error_exit "未找到有效的 SSH 公钥: $pubkey_file"
  fi

  if [ "$add_count" -gt 0 ]; then
    log "已向 $auth_file 追加 $add_count 条公钥"
  else
    log "公钥已存在于 $auth_file"
  fi

  if is_debian_13_or_newer && [ "$rsa_count" -gt 0 ] && [ "$modern_count" -eq 0 ]; then
    log "提示: 当前仅检测到 ssh-rsa 公钥；Debian 13+/新 OpenSSH 建议优先使用 ed25519 公钥。"
  fi

  owner=$(resolve_user_by_home "$user_home" 2>/dev/null || true)
  if [ -n "$owner" ]; then
    owner_group=$(id -gn "$owner" 2>/dev/null || printf "%s" "$owner")
    if ! chown "$owner":"$owner_group" "$ssh_dir" "$auth_file" 2>/dev/null; then
      log "警告: 无法自动设置 $ssh_dir 和 $auth_file 的属主，请手动检查。"
    fi
  else
    log "警告: 未识别 $user_home 对应的本地用户，已跳过属主修复。"
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

  fail2ban_port=$(get_effective_sshd_ports)
  fail2ban_port=${fail2ban_port:-ssh}

  tmpfile=$(mktemp)
  cat >"$tmpfile" <<EOF
[sshd]
enabled = true
port    = $fail2ban_port
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
用法:
  ./manage-ssh.sh
  ./manage-ssh.sh menu
  ./manage-ssh.sh help

命令模式:
  ./manage-ssh.sh 1 [github_user] [user_home]
  ./manage-ssh.sh install-github-key [github_user] [user_home]
  ./manage-ssh.sh 2 <port>
  ./manage-ssh.sh set-port <port>
  ./manage-ssh.sh 3 [user_home]
  ./manage-ssh.sh disable-password [user_home]
  ./manage-ssh.sh 4
  ./manage-ssh.sh enable-fail2ban
  ./manage-ssh.sh 5
  ./manage-ssh.sh enable-password
  ./manage-ssh.sh install-key <pubkey_file> <user_home>
EOF
}

action_install_github_key() {
  gh_user="$1"
  user_home=$(normalize_home_path "$2")

  ensure_root

  tmp=$(mktemp)
  trap 'rm -f "$tmp" 2>/dev/null || true' EXIT HUP INT TERM
  if ! fetch_github_keys "$gh_user" "$tmp"; then
    log "无法从 GitHub 获取公钥或未发现有效公钥: $gh_user"
    return 1
  fi

  install_authorized_key "$tmp" "$user_home"
  enable_pubkey_authentication "$cfg_sshd_config_path"
  safe_reload_sshd

  target_user=$(resolve_user_by_home "$user_home" 2>/dev/null || true)
  if ! verify_pubkey_authentication_enabled "$target_user"; then
    error_exit "公钥认证配置未完全生效，可能被 Match/Include 配置覆盖"
  fi

  trap - EXIT HUP INT TERM
  rm -f "$tmp" 2>/dev/null || true
}

disable_ssh_socket() {
  if command -v systemctl >/dev/null 2>&1; then
    for sock in ssh.socket sshd.socket; do
      if systemctl is-active "$sock" >/dev/null 2>&1 || systemctl is-enabled "$sock" >/dev/null 2>&1; then
        log "检测到 $sock 激活，正在禁用 socket 改用 service，以确保端口设置完全生效..."
        systemctl stop "$sock" 2>/dev/null || true
        systemctl disable "$sock" 2>/dev/null || true
        svc=$(echo "$sock" | sed 's/\.socket$/.service/')
        systemctl enable "$svc" 2>/dev/null || true
        systemctl start "$svc" 2>/dev/null || true
      fi
    done
  fi
}

action_set_ssh_port() {
  port="$1"

  ensure_root
  disable_ssh_socket
  backup_file "$cfg_sshd_config_path" >/dev/null
  set_ssh_port "$cfg_sshd_config_path" "$port"

  if ! ensure_selinux_ssh_port_context "$port"; then
    error_exit "SELinux 端口策略更新失败，已中止以避免 SSH 端口不可用"
  fi

  safe_reload_sshd

  if ! verify_ssh_port_effective "$port"; then
    diagnose_socket_activation_port_issue
    error_exit "SSH 端口修改未生效，请根据提示检查并重试"
  fi

  if ! wait_for_sshd_port_listener "$port"; then
    diagnose_socket_activation_port_issue
    error_exit "SSH 端口已写入但未检测到监听，请检查 ssh 服务状态"
  fi

  if ! ensure_firewall_port_open "$port"; then
    error_exit "SSH 端口已生效，但自动放行防火墙失败，请按提示处理"
  fi
}

action_disable_password_authentication() {
  user_home=$(normalize_home_path "$1")

  ensure_root
  if ! check_pubkey_enabled_or_keys_exist "$cfg_sshd_config_path" "$user_home"; then
    log "未检测到公钥认证或目标用户无公钥，拒绝禁用密码登录以避免被锁定"
    return 1
  fi
  disable_password_authentication "$cfg_sshd_config_path"
  safe_reload_sshd
  if ! verify_password_authentication_disabled; then
    error_exit "禁用密码登录未完全生效，可能仍被 Match/Include/socket 配置覆盖"
  fi
}

action_enable_password_authentication() {
  ensure_root
  enable_password_authentication "$cfg_sshd_config_path"
  safe_reload_sshd
}

action_configure_fail2ban() {
  ensure_root
  configure_fail2ban
}

action_install_local_key() {
  pubkey_file="$1"
  user_home=$(normalize_home_path "$2")

  ensure_root
  install_authorized_key "$pubkey_file" "$user_home"
}

run_cli_command() {
  cmd="$1"
  default_github_user=$(resolve_default_github_user)
  default_user_home=$(resolve_default_target_home)

  case "$cmd" in
    help|-h|--help)
      print_usage
      ;;
    menu)
      interactive_menu
      ;;
    1|install-github-key)
      gh_user="${2:-$default_github_user}"
      user_home="${3:-$default_user_home}"
      action_install_github_key "$gh_user" "$user_home"
      ;;
    2|set-port)
      if [ "$#" -lt 2 ]; then
        error_exit "缺少端口参数。示例: ./manage-ssh.sh set-port 2222"
      fi
      action_set_ssh_port "$2"
      ;;
    3|disable-password)
      user_home="${2:-$default_user_home}"
      action_disable_password_authentication "$user_home"
      ;;
    4|enable-fail2ban)
      action_configure_fail2ban
      ;;
    5|enable-password)
      action_enable_password_authentication
      ;;
    install-key)
      if [ "$#" -lt 3 ]; then
        error_exit "缺少参数。示例: ./manage-ssh.sh install-key ~/.ssh/id_ed25519.pub /home/user"
      fi
      action_install_local_key "$2" "$3"
      ;;
    *)
      print_usage
      error_exit "无效命令: $cmd"
      ;;
  esac
}

interactive_menu() {
  if [ ! -t 0 ]; then
    error_exit "非交互式环境，请在终端中运行"
  fi

  default_user_home=$(resolve_default_target_home)
  default_github_user=$(resolve_default_github_user)

  while :; do
    current_ports=$(get_effective_sshd_ports)
    default_port=$(printf "%s" "$current_ports" | awk -F',' '{print $1}')
    default_port=${default_port:-22}

    cat <<EOF

  请选择操作（输入对应编号；直接回车将返回菜单）:
  1) 从 GitHub 拉取并安装公钥；启用公钥登录（默认 GitHub 用户: ${default_github_user}, 目标主目录: ${default_user_home}）
  2) 设置 sshd 端口 (当前: ${current_ports})
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
        if ! action_install_github_key "$gh_user" "$user_home"; then
          :
        fi
        ;;
      2)
        printf "请输入新的 sshd 端口 (回车使用 %s): " "$default_port"
        read -r port || port="$default_port"
        port=${port:-$default_port}
        action_set_ssh_port "$port"
        ;;
      3)
        printf "目标用户主目录（回车使用 %s）: " "$default_user_home"
        read -r user_home || user_home="$default_user_home"
        user_home=${user_home:-$default_user_home}
        if ! action_disable_password_authentication "$user_home"; then
          :
        fi
        ;;
      4)
        if ! action_configure_fail2ban; then
          :
        fi
        ;;
      5)
        action_enable_password_authentication
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
  load_os_release_info

  if [ "$#" -eq 0 ]; then
    interactive_menu
  else
    run_cli_command "$@"
  fi
  exit 0
}

main "$@"
