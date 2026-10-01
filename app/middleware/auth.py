from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings

class ApiKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Public paths: health probe, docs, and the login flow (browser
        # has no X-API-Key; it authenticates via session cookies instead).
        if path in ("/health", "/docs", "/openapi.json") or path.startswith("/auth/"):
            return await call_next(request)
        
        settings = get_settings()
        api_key = request.headers.get("X-API-Key", "")
        valid_keys = [k.strip() for k in settings.API_KEYS.split(",") if k.strip()]
        
        if valid_keys and api_key not in valid_keys:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"}
            )
        return await call_next(request)
