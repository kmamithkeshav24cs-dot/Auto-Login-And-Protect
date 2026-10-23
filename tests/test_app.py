from types import SimpleNamespace
from unittest.mock import patch

import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


class FakeSupabaseAuth:
    def __init__(self, *, invalid_login=False, invalid_refresh=False):
        self.invalid_login = invalid_login
        self.invalid_refresh = invalid_refresh

    def sign_up(self, payload):
        return SimpleNamespace(
            user={
                "id": "user-123",
                "email": payload["email"],
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

    def sign_in_with_password(self, payload):
        if self.invalid_login or payload["password"] == "wrong":
            raise ValueError("bad credentials")
        return SimpleNamespace(
            session=SimpleNamespace(access_token="demo-token", refresh_token="demo-refresh"),
            user={
                "id": "user-123",
                "email": payload["email"],
                "created_at": "2024-01-01T00:00:00Z",
            },
        )

    def get_user(self, token):
        if token == "bad-token":
            raise ValueError("invalid token")
        return SimpleNamespace(
            user={
                "id": "user-123",
                "email": "test@example.com",
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

    def sign_out(self):
        return True

    def refresh_session(self, refresh_token):
        if self.invalid_refresh or refresh_token != "demo-refresh":
            raise ValueError("refresh failed")
        return SimpleNamespace(
            session=SimpleNamespace(access_token="fresh-token", refresh_token="fresh-refresh")
        )


class FakeSupabase:
    def __init__(self, *, invalid_login=False, invalid_refresh=False):
        self.auth = FakeSupabaseAuth(invalid_login=invalid_login, invalid_refresh=invalid_refresh)


def test_public_info():
    with patch.object(main, "supabase", FakeSupabase()):
        response = client.get("/public/info")
    assert response.status_code == 200
    assert response.json()["message"] == "Welcome stranger! This info is public."


def test_signup_success():
    with patch.object(main, "supabase", FakeSupabase()):
        response = client.post("/auth/signup", json={"email": "user@example.com", "password": "secret123"})
    assert response.status_code == 201
    assert response.json()["user"]["email"] == "user@example.com"


def test_login_and_profile():
    with patch.object(main, "supabase", FakeSupabase()):
        login_response = client.post("/auth/login", json={"email": "test@example.com", "password": "secret123"})
        assert login_response.status_code == 200
        assert login_response.json()["access_token"] == "demo-token"

        profile_response = client.get(
            "/protected/profile",
            headers={"Authorization": "Bearer demo-token"},
        )
    assert profile_response.status_code == 200
    assert profile_response.json()["email"] == "test@example.com"


def test_missing_token_returns_401():
    with patch.object(main, "supabase", FakeSupabase()):
        response = client.get("/protected/profile")
    assert response.status_code == 401
    assert response.json()["error"] == "Access token required"


def test_invalid_token_returns_401():
    with patch.object(main, "supabase", FakeSupabase()):
        response = client.get(
            "/protected/profile",
            headers={"Authorization": "Bearer bad-token"},
        )
    assert response.status_code == 401
    assert response.json()["error"] == "Invalid or expired token"


def test_login_rate_limit():
    main.login_attempts.clear()
    with patch.object(main, "supabase", FakeSupabase(invalid_login=True)):
        for _ in range(5):
            response = client.post("/auth/login", json={"email": "test@example.com", "password": "wrong123"})
            assert response.status_code == 401
        limited = client.post("/auth/login", json={"email": "test@example.com", "password": "wrong123"})
    assert limited.status_code == 429
    assert limited.json()["error"].startswith("Too many failed login attempts")


def test_refresh_token_flow():
    with patch.object(main, "supabase", FakeSupabase()):
        response = client.post("/auth/refresh", json={"refresh_token": "demo-refresh"})
    assert response.status_code == 200
    assert response.json()["access_token"] == "fresh-token"
