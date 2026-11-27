"""ARYAN CYBERSHIELD AI - FastAPI entrypoint. Project Developed By: Aryan."""
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import PROJECT_AUTHOR, PROJECT_NAME, PROJECT_SUBTITLE, get_settings
from app.core.limiter import limiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("cybershield")


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title=PROJECT_NAME, description=PROJECT_SUBTITLE, version="1.0.0",
                  docs_url=None if s.is_production else "/docs",
                  redoc_url=None if s.is_production else "/redoc")
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(CORSMiddleware, allow_origins=s.cors_list, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("Unhandled error on %s", request.url.path)  # no request bodies/credentials logged
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    from app.api import analysis, approvals, auth, dashboard, incidents, investigations, knowledge  # noqa: E402
    for r in (auth.router, analysis.router, investigations.router, knowledge.router, incidents.router, approvals.router, dashboard.router):
        app.include_router(r)

    @app.get("/api/health", tags=["system"])
    def health():
        return {"status": "ok", "app": PROJECT_NAME, "author": PROJECT_AUTHOR, "demo_mode": s.demo_mode}

    return app


app = create_app()
