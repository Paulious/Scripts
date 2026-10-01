from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import get_settings
from app.patterns import get_library


def create_app() -> FastAPI:
    settings = get_settings()
    get_library()  # fail fast at start-up if a pattern file is broken

    app = FastAPI(
        title="Deployment Log Analyzer",
        version="1.0.0",
        description="Stateless analysis of Intune / Windows deployment logs. Nothing is stored.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def no_store(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.include_router(router)
    return app


app = create_app()
