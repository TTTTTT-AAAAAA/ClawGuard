from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import admin_routes, audit_routes, auth_routes, policy_routes, review_routes, task_routes
from .database import init_db


app = FastAPI(title="ClawGuard Web", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router, prefix="/api/auth", tags=["auth"])
app.include_router(task_routes.router, prefix="/api/tasks", tags=["tasks"])
app.include_router(review_routes.router, prefix="/api/reviews", tags=["reviews"])
app.include_router(audit_routes.router, prefix="/api/audit", tags=["audit"])
app.include_router(policy_routes.router, prefix="/api/policies", tags=["policies"])
app.include_router(admin_routes.router, prefix="/api/admin", tags=["admin"])


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "clawguard-web"}
