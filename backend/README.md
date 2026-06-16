# Backend

## Run

```powershell
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

初始化数据库在应用启动时自动完成，并创建默认用户。

## Key APIs

- `POST /api/auth/login`
- `POST /api/auth/challenge`
- `POST /api/auth/cfl-login`
- `POST /api/tasks`
- `GET /api/tasks/{job_id}`
- `GET /api/tasks/{job_id}/logs`
- `GET /api/tasks/{job_id}/result`
- `GET /api/audit`
- `GET /api/policies`

## Security Notes

- 用户只能提交 action，不能提交任意 shell 命令。
- Docker 命令使用数组形式，不使用 `shell=True`。
- 输入内容先经过过滤器，日志写入前脱敏。
- 真实 CFL DLL 不存在时自动使用 mock 模式。
