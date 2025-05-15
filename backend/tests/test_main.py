import os
import jwt
import pytest
from fastapi.testclient import TestClient
from datetime import timedelta, datetime, timezone

from app.main import app  

client = TestClient(app)

SECRET = os.getenv("JWT_SECRET", "TEST")  

def make_token(payload: dict = None, expired: bool = False) -> str:
    if payload is None:
        payload = {"sub": "pytest-user"}

    now = datetime.now(timezone.utc)
    exp = now - timedelta(minutes=5) if expired else now + timedelta(hours=1)
    payload.update({"exp": exp})
    return jwt.encode(payload, SECRET, algorithm="HS256")

def test_missing_authorization_header():
    r = client.get("/users")
    assert r.status_code == 400
    assert r.json()["detail"] == "Authorization header missing"

def test_malformed_authorization_header():
    r = client.get("/", headers={"Authorization": "Bearer"})
    assert r.status_code == 400
    assert "Invalid authorization header format" in r.json()["detail"]

    r2 = client.get("/", headers={"Authorization": "Token abc"})
    assert r2.status_code == 400
    assert "Invalid authorization header format" in r2.json()["detail"]

def test_invalid_token():
    r = client.get("/users", headers={"Authorization": "Bearer not.a.valid.token"})
    assert r.status_code == 401
    assert "Invalid token" in r.json()["detail"]

def test_expired_token():
    token = make_token(expired=True)
    r = client.get("/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json() == {"detail": "Token expired"}


def test_valid_token_allows_access_root():
    token = make_token()
    r = client.get("/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"message": "Server running"}

def test_valid_token_allows_access_users():
    token = make_token({"sub": "user42"})
    r = client.get("/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"message": "Getting the users"}


def test_payload_too_large():
    oversize = 500_001
    payload = b"x" * oversize
    token = make_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Length": str(10)
    }
    r = client.post("/users", data=payload, headers=headers)
    assert r.status_code == 413
    assert r.json() == {"detail": "Payload too large"}

def test_headers_too_large():
    oversize = 500_001
    payload = b"x" * 10
    token = make_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Length": str(oversize)
    }
    r = client.post("/users", data=payload, headers=headers)
    assert r.status_code == 413
    assert r.json() == {"detail": "Payload too large"}


def test_user_get_post():
    token = make_token({"sub": "user42"})
    r = client.get("/post", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"message": "Getting post"}


def test_user_registration_success(): 
    token = make_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type" : "application/json"
    }
    payload = {
        "email" : "test@test.com",
        "password" : "jesuisunmotdepasse"
    }

    r = client.post("/register", json=payload, headers=headers)
    assert r.status_code == 200
    assert r.json() == {"message" : "Account created"}

def test_user_registration_bad_email(): 
    token = make_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type" : "application/json"
    }
    payload = {
        "email" : "test",
        "password" : "jesuisunmotdepasse"
    }

    r = client.post("/register", json=payload, headers=headers)
    assert r.status_code == 422

def test_user_registration_bad_password():
    token = make_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type" : "application/json"
    }
    payload = {
        "email" : "test@test.com",
        "password" : "test"
    }

    r = client.post("/register", json=payload, headers=headers)
    assert r.status_code == 422
