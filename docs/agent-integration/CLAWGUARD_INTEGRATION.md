# ClawGuard Agent Integration Interface

这个接口定义了 **OpenClaw Agent（主 Agent）** 与 **ClawGuard 安全审计系统** 之间的交互契约。

## 架构概览

```
┌──────────────────────────────────────┐
│         ClawGuard Web Console        │
│  (FastAPI Backend + Bootstrap UI)    │
│  端口 8000                           │
│  ┌──────────────┐ ┌──────────────┐  │
│  │ /api/reviews │ │ /api/audit   │  │
│  └──────┬───────┘ └──────┬───────┘  │
└─────────┼─────────────────┼─────────┘
          │ POST            │ GET
          ▼                 ▼
┌──────────────────────────────────────┐
│   OpenClaw Agent (main)              │
│   Host: SWIFTIE-YYR (WSL2)          │
│                                      │
│   clawguard-integration/             │
│   ├── clawguard-agent.yaml          │ ← 行为合规策略
│   ├── clawguard-security-baseline.yaml ← 安全基线
│   ├── clawguard-audit.sh            │ ← 合规检查脚本
│   └── reports/                      │ ← 审计报告存档
└──────────────────────────────────────┘
```

## 接口文件

### 1. `clawguard-agent.yaml` — 行为合规策略

定义 Agent 的行为边界：

| 类别 | 规则数 | 说明 |
|------|--------|------|
| Filesystem | 3 | 禁止修改工作区外文件，禁止暴力删除 |
| Network | 2 | 禁止外泄敏感数据，限制外调用具 |
| Execution | 3 | 禁止破坏性命令，Docker/系统变更需审核 |
| Data | 2 | 禁止读取私钥/凭据，禁止数据外泄 |
| Audit | 2 | 每次外部操作需留日志，群聊需声明身份 |

- **12条行为规则**（5条禁止、3条需审批、4条审计要求）
- 角色模型 `audited_agent` 定义了允许/拒绝的工具集
- 集成配置指向 ClawGuard 后端的 API 端点

### 2. `clawguard-security-baseline.yaml` — 安全基线

定义宿主机的预期安全配置：

| 检查 ID | 项目 | 严重度 | 预期状态 |
|---------|------|--------|---------|
| CHK-001 | OS Security Updates | high | 无未安补丁 |
| CHK-002 | Non-Loopback Ports | high | 0 |
| CHK-003 | SSH Server Status | medium | 未运行 |
| CHK-004 | Workspace Permissions | medium | 750, admin_linux |
| CHK-005 | ClawGuard File Integrity | high | 0 未提交变更 |
| CHK-006 | Root Password Status | high | 无密码登录 |
| CHK-007 | World-Readable Files | medium | 0 |
| CHK-008 | Policy Integrity | critical | SHA256 匹配 |

### 3. `clawguard-audit.sh` — 审计集成脚本

```bash
# 运行全部安全检查（输出 JSON 到 stdout）
./clawguard-audit.sh

# 运行 + 推送到 ClawGuard 后端
./clawguard-audit.sh --ship

# 查看策略摘要
./clawguard-audit.sh --policy

# 查看主机信息
./clawguard-audit.sh --host
```

## 使用方式

### 方式 A：ClawGuard 后端未启动（仅本地）

脚本会自动检测后端是否运行。没启动时，审计报告保存在 `reports/latest-audit.json`。

### 方式 B：ClawGuard 后端已启动

```bash
# 1. 启动 ClawGuard 后端（在 Windows 上）
cd D:\clawguard\backend
.venv\Scripts\activate
uvicorn app.main:app --reload

# 2. 从 WSL2 推送审计数据
cd ~/clawguard-integration
bash clawguard-audit.sh --ship

# 3. 在 ClawGuard 前端 (frontend/index.html) 查看审计记录
```

### 方式 C：定时自动审计（cron）

```bash
# 每天 9:00 和 21:00 推送审计
crontab -e
# 添加：
0 9,21 * * * /home/admin_linux/.openclaw/workspace/clawguard-integration/clawguard-audit.sh --ship >> /home/admin_linux/.openclaw/workspace/clawguard-integration/reports/cron.log 2>&1
```

## Agent 行为日志格式

每次 Agent 执行外部操作时，应记录以下事件到 ClawGuard：

```json
{
  "agent_id": "openclaw-main",
  "timestamp": "2026-06-16T11:35:00Z",
  "event_type": "AGENT_ACTION",
  "action": "tool_execution",
  "tool": "exec",
  "command": "ls -la /etc",
  "resource": "/etc",
  "result": "success",
  "risk_level": "low",
  "session_id": "sess_abc123"
}
```

## 审计追踪链路

1. Agent 发起操作
2. 对比 `clawguard-agent.yaml` 行为规则检查合规性
3. 如果需要审核 → POST `/api/reviews/capture` 捕获到 ClawGuard
4. ClawGuard 管理员审核（同意/拒绝/修改）
5. 操作执行后 → 记录 AuditLog
6. 定期运行 `clawguard-audit.sh --ship` 上报安全基线状态

## 安全配置检查结果（快照）

最后运行时间：2026-06-16 11:43 UTC

| 检查 | 结果 | 说明 |
|------|------|------|
| ✅ OS Updates | pass | 无待安装安全补丁 |
| ❌ Non-Loopback Ports | fail | WSL2 DNS (10.255.255.254:53) — 正常 WSL2 行为 |
| ⚠️ SSH | warn | SSH 未运行 ✅ |
| ✅ Workspace Perms | pass | 775 admin_linux |
| ❌ ClawGuard Integrity | fail | 项目尚未 git add（首次检出正常） |
| ✅ Root Password | pass | 无密码登录 |
| ⚠️ World-Readable Files | warn | `.npm-global` 等工作文件 — 低风险 |
| ℹ️ Policy Integrity | info | SHA256 记录中 |
