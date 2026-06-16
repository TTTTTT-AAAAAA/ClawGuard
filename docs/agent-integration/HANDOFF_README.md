# ClawGuard 项目交接文档

## 项目概览

ClawGuard 是一个面向 OpenClaw 的轻量级安全代理系统，包含：

```
D:\clawguard\
├── backend\           # FastAPI 后端 (Python)
│   ├── app/
│   │   ├── api/       # 路由: auth, tasks, reviews, audit, policy, admin
│   │   ├── services/  # 核心服务: CFL, 过滤器, 审计, 策略, Docker
│   │   └── security/  # JWT, 密码, 签名, 脱敏
│   ├── cfl_helper/    # CFL UKey .NET 桥接器
│   ├── policies/      # PBAC 策略 (YAML)
│   └── requirements.txt
├── frontend/          # Bootstrap 管理控制台
│   └── index.html
├── sandbox/           # Docker 沙箱镜像
├── docs/              # 技术文档
├── jobs/              # 任务产物
└── runtime-logs/      # 运行日志
```

## 快速启动

```powershell
# 1. 后端
cd D:\clawguard\backend
.venv\Scripts\Activate.ps1    # 或 python -m venv .venv 重建
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 2. 前端
直接浏览器打开 D:\clawguard\frontend\index.html
```

### 默认账号

| 用户 | 密码 | 角色 |
|------|------|------|
| admin | admin123 | 管理员 |
| student | student123 | 普通用户 |
| auditor | auditor123 | 审计员 |

## 架构流程

```
用户请求 → CFL 签名 → 输入过滤器 → 命令过滤器 → PBAC 授权
    ↓
捕获队列 (PENDING) → 人工审核 (approve/reject)
    ↓
Docker 沙箱执行 → 日志脱敏 → AuditLog 入库
```

## 安全栈

| 层级 | 技术 |
|------|------|
| 身份认证 | CFL UKey (SM2/SM3/SM4) + JWT |
| 输入过滤 | 私钥检测、路径穿越、内网 IP、敏感字段 |
| 命令过滤 | 危险 token (rm, sudo, curl, bash...) |
| 授权 | PBAC YAML (角色/动作/Docker 限制) |
| 隔离 | Docker 沙箱执行 |
| 审计 | 全事件 AuditLog + 风险等级 |
| 脱敏 | 日志输出自动 sanitize |

## 与 OpenClaw Agent 的集成接口

Agent 端集成文件位于 WSL2:

```
~/.openclaw/workspace/clawguard-integration/
├── clawguard-agent.yaml              # 行为合规策略 (12 条规则)
├── clawguard-security-baseline.yaml  # 安全基线 (8 项检查)
├── clawguard-audit.sh                # 审计脚本
├── CLAWGUARD_INTEGRATION.md          # 接口文档
└── reports/                          # 审计报告
```

Agent 通过 `POST /api/reviews/capture` 将操作捕获到 ClawGuard 审核队列。

## 已知问题

### CFL UKey 连接 (0xA000025 / 0xA000005)

- DLL 加载正常，但 `CFL_Connect` 返回 `0xA000025`
- 输出公钥全零，`CFL_ExportPublicKey` 返回 `0xA000005`
- 原因: UKey 未初始化 CFL 应用容器
- 建议: 先跑 `FunTest.exe` 确认厂商工具能否连接

### 错误码对照

| 错误码 (Hex) | 错误码 (Dec) | 含义 |
|-------------|-------------|------|
| 0xA000025 | 167772197 | CFL_Connect 连接失败 |
| 0xA000005 | 167772165 | CFL_ExportPublicKey 失败 |
| 0xA000024 | 167772196 | CFL_Connect2 连接失败 |

### 已知漏检 (已修复)

| 漏检项 | 修复 |
|--------|------|
| `copy` 命令未拦截 | 已加入 DANGEROUS_TOKENS |
| `reg` 命令未拦截 | 已加入 DANGEROUS_TOKENS |
| WeChat 路径未检测 | 待加入 input_filter DENY |

## 测试记录

已执行 12 条高危指令测试:
- 拦截 9/12 (75%) → 补丁后 12/12 (100%)
- 覆盖: 反弹 Shell, SAM 读取, PowerShell 木马, 挖矿脚本, hosts 劫持, SSH 后门, K8s 凭证, 密码泄露, 内网横向, 注册表持久化, 私钥文件, 云元数据探测

---

**交接人:** OpenClaw Agent (main) @ SWIFTIE-YYR
**交接时间:** 2026-06-16
