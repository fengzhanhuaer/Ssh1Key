# SSH 管理脚本 (Ssh1Key)

一个用于管理 SSH 配置的 POSIX shell 脚本，支持公钥管理、端口配置、密码登录控制和 fail2ban 部署。

## 功能特性

- ✅ 从 GitHub 拉取并安装公钥，启用公钥登录
- ✅ 修改 SSH 端口
- ✅ 禁用/启用密码登录（智能检测公钥登录状态，避免锁定）
- ✅ 安装本地公钥到指定用户
- ✅ 自动安装并配置 fail2ban 以增强安全性
- ✅ 交互式菜单界面，方便操作
- ✅ 自动备份配置文件，确保安全
- ✅ 支持多种 Linux 发行版

## 从 GitHub 拉取脚本并执行

### 安全下载流程（推荐）

1. **下载脚本**
   ```bash
   # 使用 curl 下载
   curl -fsSL https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh -o manage-ssh.sh
   
   # 或使用 wget 下载
   wget -q https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh
   ```

2. **查看脚本内容（重要）**
   ```bash
   # 查看脚本内容，确保安全
   cat manage-ssh.sh
   
   # 或使用更安全的方式检查脚本
   less manage-ssh.sh
   ```

3. **赋予执行权限**
   ```bash
   chmod +x manage-ssh.sh
   ```

4. **执行脚本**
   ```bash
   sudo ./manage-ssh.sh [命令] [参数]
   ```

### 一键执行（不推荐用于不可信来源）

```bash
# 使用 curl 一键执行（不带参数，自动进入交互式菜单）
curl -fsSL https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh | sudo bash

# 使用 wget 一键执行（不带参数，自动进入交互式菜单）
wget -q -O - https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh | sudo bash

# 使用 curl 带参数执行
curl -fsSL https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh | sudo bash -s -- [命令] [参数]

# 使用 wget 带参数执行
wget -q -O - https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh | sudo bash -s -- [命令] [参数]

# 示例：一键设置 SSH 端口为 2222
curl -fsSL https://raw.githubusercontent.com/fengzhanhuaer/Ssh1Key/main/manage-ssh.sh | sudo bash -s -- set-port 2222
```

## 命令说明

| 命令 | 参数 | 描述 |
|------|------|------|
| `1` | `<github-user> [home]` | 从 GitHub 拉取并安装公钥（可选指定目标主目录，默认 /root），并启用公钥登录 |
| `3` | `[home]` | 禁用密码登录（仅在检测到公钥认证或目标用户已有公钥时执行） |
| `4` | 无 | 安装（如需）并部署 fail2ban sshd jail |
| `5` | 无 | 启用密码登录（并允许 root 密码登录） |
| `set-port` | `<port>` | 设置 sshd 端口 |
| `install-key` | `<pubkey> <home>` | 将本地公钥文件安装到指定用户主目录 |
| `enable-fail2ban` | 无 | 安装（如需）并部署 fail2ban sshd jail（与命令 `4` 功能相同） |
| `menu` | 无 | 启动交互式菜单 |
| `help` | 无 | 显示帮助信息 |

## 使用示例

### 1. 从 GitHub 拉取并安装公钥

```bash
# 使用默认 GitHub 用户和主目录
sudo ./manage-ssh.sh 1

# 指定 GitHub 用户
sudo ./manage-ssh.sh 1 john_doe

# 指定 GitHub 用户和目标主目录
sudo ./manage-ssh.sh 1 john_doe /home/john
```

### 2. 设置 SSH 端口

```bash
# 设置端口为 2222
sudo ./manage-ssh.sh set-port 2222
```

### 3. 安装本地公钥

```bash
# 安装本地公钥到用户主目录
sudo ./manage-ssh.sh install-key ~/.ssh/id_rsa.pub /home/john
```

### 4. 禁用密码登录

```bash
# 使用默认主目录
sudo ./manage-ssh.sh 3

# 指定主目录
sudo ./manage-ssh.sh 3 /home/john
```

### 5. 启用密码登录

```bash
sudo ./manage-ssh.sh 5
```

### 6. 安装并配置 fail2ban

```bash
# 使用数字命令
sudo ./manage-ssh.sh 4

# 或使用完整命令
sudo ./manage-ssh.sh enable-fail2ban
```

### 7. 启动交互式菜单

```bash
sudo ./manage-ssh.sh menu
```

## 注意事项

1. **权限要求**：脚本需要以 root 或具备相应权限的用户运行
2. **安全警告**：禁用密码登录前，请确保已正确配置公钥登录，避免被锁定
3. **配置备份**：脚本会自动备份修改的配置文件到 `/var/backups/ssh-manager/` 目录
4. **系统支持**：支持的 Linux 发行版包括但不限于：
   - Ubuntu/Debian
   - CentOS/RHEL/Fedora
   - Arch Linux
   - openSUSE
   - Alpine Linux
5. **网络要求**：从 GitHub 拉取公钥时需要网络连接
6. **fail2ban**：自动检测包管理器并安装 fail2ban（如果尚未安装）

## 安全建议

1. **始终验证脚本**：在执行前务必查看脚本内容，确保其来源可信
2. **使用非默认端口**：更改默认 SSH 端口可以减少大部分自动攻击
3. **启用公钥登录**：公钥登录比密码登录更安全
4. **使用 fail2ban**：可以有效防止暴力破解攻击
5. **定期更新**：定期检查脚本更新，确保使用最新版本

## 许可证

[MIT License](LICENSE)

## 贡献

欢迎提交 Issue 和 Pull Request！