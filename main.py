from fastapi import FastAPI
from routers import access

app = FastAPI(
    title="Sentinel Access",
    description="AI Compliance Copilot — Interceptor & Policy Engine",
    version="0.1.0"
)

app.include_router(access.router)

@app.get("/")
def root():
    return {"status": "Sentinel Access online"}