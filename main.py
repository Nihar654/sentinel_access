from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import access

app = FastAPI(
    title="Sentinel Access",
    description="AI Compliance Copilot — Interceptor & Policy Engine",
    version="0.1.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(access.router)

@app.get("/")
def root():
    return {"status": "Sentinel Access online"}