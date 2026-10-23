import os
import time
from collections import defaultdict
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import HTTPException as FastAPIHTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
PORT = int(os.getenv("PORT", "8000"))

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_KEY in the environment.")

try:
    supabase: Client | None = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception:  # pragma: no cover - fails only when env vars are not real Supabase credentials.
    supabase = None

app = FastAPI(
    title="Auth · Login & Protect",
    version="1.0.0",
    description="Secure Supabase-backed authentication API with protected routes and Swagger documentation.",
)

security = HTTPBearer(auto_error=False)
login_attempts: dict[str, list[float]] = defaultdict(list)


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class PublicInfoResponse(BaseModel):
    message: str


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "Bad Request"})


@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(_, exc: FastAPIHTTPException):
    payload: dict[str, Any]
    if isinstance(exc.detail, dict):
        payload = exc.detail
    else:
        payload = {"error": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=payload)


def normalize_user_data(user: Any) -> dict[str, Any]:
    if user is None:
        return {}
    if isinstance(user, dict):
        return user
    if hasattr(user, "model_dump"):
        return user.model_dump()
    if hasattr(user, "dict"):
        return user.dict()
    if hasattr(user, "__dict__"):
        return dict(user.__dict__)
    return {"value": str(user)}


def ensure_supabase_configured() -> None:
    if supabase is None:
        raise HTTPException(status_code=500, detail="Supabase is not configured. Add valid SUPABASE_URL and SUPABASE_KEY values.")


def check_login_rate_limit(client_ip: str) -> None:
    now = time.time()
    attempts = login_attempts[client_ip]
    attempts[:] = [timestamp for timestamp in attempts if now - timestamp < 60]
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Please wait 60 seconds before trying again.")


def record_failed_login(client_ip: str) -> None:
    now = time.time()
    attempts = login_attempts[client_ip]
    attempts[:] = [timestamp for timestamp in attempts if now - timestamp < 60]
    attempts.append(now)


def clear_login_attempts(client_ip: str) -> None:
    login_attempts.pop(client_ip, None)


async def require_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
    ensure_supabase_configured()
    if credentials is None:
        raise HTTPException(status_code=401, detail="Access token required")

    token = credentials.credentials
    try:
        user_result = supabase.auth.get_user(token)
        user = getattr(user_result, "user", None)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return normalize_user_data(user)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def require_admin(current_user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
    app_metadata = current_user.get("app_metadata") or {}
    user_metadata = current_user.get("user_metadata") or {}
    role = app_metadata.get("role") or user_metadata.get("role")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return current_user


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/public/info")
async def public_info() -> PublicInfoResponse:
    return PublicInfoResponse(message="Welcome stranger! This info is public.")


@app.post("/auth/signup", status_code=status.HTTP_201_CREATED)
async def sign_up(payload: SignupRequest) -> dict[str, Any]:
    ensure_supabase_configured()
    try:
        response = supabase.auth.sign_up({"email": payload.email, "password": payload.password})
        user = getattr(response, "user", None)
        return {"user": normalize_user_data(user) if user is not None else response}
    except Exception as exc:  # pragma: no cover - defensive fallback
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/auth/login")
async def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
    ensure_supabase_configured()
    client_ip = request.client.host if request.client else "unknown"
    check_login_rate_limit(client_ip)

    try:
        response = supabase.auth.sign_in_with_password({
            "email": payload.email,
            "password": payload.password,
        })
    except Exception:
        record_failed_login(client_ip)
        raise HTTPException(status_code=401, detail="Invalid login credentials")

    session = getattr(response, "session", None)
    if session is None:
        record_failed_login(client_ip)
        raise HTTPException(status_code=401, detail="Invalid login credentials")

    clear_login_attempts(client_ip)
    user = normalize_user_data(getattr(response, "user", None))
    return {
        "access_token": getattr(session, "access_token", None),
        "refresh_token": getattr(session, "refresh_token", None),
        "user": user,
    }


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(current_user: dict[str, Any] = Depends(require_auth)) -> None:
    ensure_supabase_configured()
    try:
        supabase.auth.sign_out()
    except Exception:
        pass
    return None


@app.get("/protected/profile")
async def protected_profile(current_user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
    return {
        "id": current_user.get("id"),
        "email": current_user.get("email"),
        "created_at": current_user.get("created_at"),
    }


@app.get("/protected/dashboard")
async def dashboard(current_user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
    return {
        "message": "Welcome to your dashboard.",
        "user_id": current_user.get("id"),
    }


@app.get("/protected/admin")
async def admin_area(current_user: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    return {
        "message": "Admin access granted.",
        "user": current_user,
    }


@app.post("/auth/refresh")
async def refresh(payload: RefreshRequest) -> dict[str, Any]:
    ensure_supabase_configured()
    try:
        response = supabase.auth.refresh_session(payload.refresh_token)
        session = getattr(response, "session", None)
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        return {
            "access_token": getattr(session, "access_token", None),
            "refresh_token": getattr(session, "refresh_token", None),
        }
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
