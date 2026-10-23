# Auth · Login & Protect

This project follows the Week 2 authentication assignment from the PDF: a secure API built with FastAPI and Supabase Auth. It covers sign up, login, logout, protected routes, bearer-token validation, Swagger UI, rate limiting, refresh tokens, and a 403 forbidden example.

## Overview

The API protects user-only endpoints with a reusable auth dependency and uses Supabase as the identity provider. The server never hashes or stores passwords itself; it delegates that work to Supabase.

## Tech stack

- Python 3.10+
- FastAPI
- Supabase Python SDK
- Swagger UI via FastAPI /docs
- Python-dotenv for environment variables

## Environment setup

1. Create a free Supabase project.
2. Copy your Project URL and anon key from `Project Settings -> API`.
3. Copy `.env.example` to `.env` and set your values:

```bash
cp .env.example .env
```

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
PORT=8000
```

Important: keep `.env` out of Git. It is already ignored in `.gitignore`.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API is served on:

- http://localhost:8000
- Swagger docs: http://localhost:8000/docs

## API reference

| Route | Method | Auth required | Purpose |
| --- | --- | --- | --- |
| `/public/info` | GET | No | Public information |
| `/auth/signup` | POST | No | Register a user with Supabase |
| `/auth/login` | POST | No | Sign in and receive access + refresh tokens |
| `/auth/logout` | POST | Yes | End the session |
| `/protected/profile` | GET | Yes | Return the current user profile |
| `/protected/dashboard` | GET | Yes | Example protected dashboard route |
| `/protected/admin` | GET | Yes + admin role | Example 403 case |
| `/auth/refresh` | POST | No | Exchange a refresh token for a new access token |

## Security notes

- `401 Unauthorized` means the client is not known or the token is missing/invalid.
- `403 Forbidden` means the user is authenticated but not allowed to access that route.
- Access tokens are short-lived by design; refresh tokens are used to get a fresh one without re-entering credentials.
- `/auth/login` is rate-limited to avoid brute-force attacks.

## Swagger

The app exposes automatic Swagger UI at `/docs`. Protected endpoints use bearer auth, so the lock icon appears in the documentation and the token can be pasted once for quick testing.

## Git and secrets

Never commit your `.env` file. Keep only the key names in `.env.example` and commit that instead. This avoids exposing Supabase credentials in Git history.

## Bonus / stretch

This project includes the stretch goals from the assignment:

- 403 forbidden example on `/protected/admin`
- refresh-token endpoint at `/auth/refresh`
- rate limiting on login attempts
- README + environment documentation

## Example curl flow

```bash
curl -i -X POST http://localhost:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

curl -i -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

curl -i http://localhost:8000/protected/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```
