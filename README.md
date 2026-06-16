# ClawGuard Web

ClawGuard Web 是面向 OpenClaw 的轻量级安全代理系统。它把用户任务放进一条固定防护链：认证、CFL 签名校验、输入过滤、命令过滤、PBAC 授权、Docker 沙箱执行、日志脱敏和审计告警。

## 融合参考

- ClawSandbox 思路：沙箱隔离、凭证可信、最小权限、审计闭环。
- Caramel-Pudding 思路：安全检测 GUI、风险评分、检测结果、报告化展示和可演示的修复建议。

## 技术栈

- Backend: FastAPI, SQLAlchemy, SQLite, PyJWT/python-jose, passlib, Docker SDK, PyYAML
- Frontend: Bootstrap 静态控制台
- Sandbox: Docker + OpenClaw stub
- Policy: YAML PBAC

## 快速启动

```powershell
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

浏览器打开 `frontend/index.html`，默认后端地址为 `http://127.0.0.1:8000`。

默认账号：

- `admin / admin123`
- `student / student123`
- `auditor / auditor123`

## CFL 接入

默认使用 `CLAWGUARD_CFL_MODE=mock`，没有 UKey 或 DLL 时也能完整演示。

真实 UKey 模式：

```env
CLAWGUARD_CFL_MODE=real
CLAWGUARD_CFL_DLL_PATH=./CFLClientLib.dll
```

将 CFL 厂商 DLL 放到 `backend/CFLClientLib.dll`。后端提供 `GET /api/auth/cfl/status` 查看 DLL 是否存在、是否可加载、DLL 架构和错误信息。

注意：当前教学包里的 `CFLClientLib.dll` 是 x86 DLL。如果后端使用 64 位 Python，会返回 `WinError 193`。真实接入需要提供 x64 DLL，或改用 32 位 Python/独立 32 位签名助手承载 CFL 调用。

构建沙箱镜像：

```powershell
docker build -t openclaw-sandbox:latest ./sandbox
```

Docker Compose：

```powershell
docker compose up --build
```

## 演示路径

1. 管理员登录。
2. 提交 `run_openclaw`，输入正常 JSON。
3. 查看任务状态、日志、结果。
4. 输入 `token=abc` 观察脱敏审计。
5. 输入 `../etc/passwd` 或私钥片段观察输入拦截。
6. 在参数里写 `curl http://example.com` 观察命令过滤拦截。
7. 用 `student` 访问审计接口，观察 PBAC 拒绝。
