## 快速开始（片段）

本项目提供一个用于管理 SSH 的 POSIX shell 脚本 `manage-ssh.sh`，支持：
- 禁用密码登录与禁止 root 登录
- 修改 SSH 端口
- 安装公钥到指定用户
- 可选部署 fail2ban 的安全配置

示例：
sudo ./manage-ssh.sh disable-password
sudo ./manage-ssh.sh set-port 2222
sudo ./manage-ssh.sh install-key /path/to/pubkey /root

## 从 GitHub 一键拉取并执行脚本（示例）

下面提供几种获取并运行 `manage-ssh.sh` 的常见方法。强烈建议在执行前先审查脚本内容并验证来源/校验和；避免直接在不可信网络环境下使用“管道到 shell”的一键命令。

1) 推荐（安全）流程 — 下载、查看、执行：
