import os
import jwt

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
