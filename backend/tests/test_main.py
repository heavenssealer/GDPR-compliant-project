# tests/test_app.py
import os
import jwt
import certifi
import asyncio
import pytest

from datetime import timedelta, datetime, timezone

from fastapi.testclient import TestClient


from app.main import app  


import app.database.db as db_module 
from app.database.db import connect_to_db, ServerApi


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
        "Content-Type": "application/json",
    }
    payload = {"email": "test", "password": "jesuisunmotdepasse"}

    r = client.post("/register", json=payload, headers=headers)
    assert r.status_code == 422


def test_user_registration_bad_password():
    token = make_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"email": "test@test.com", "password": "test"}

    r = client.post("/register", json=payload, headers=headers)
    assert r.status_code == 422




class DummyClient:
    def __init__(self, *args, **kwargs):
        self._init_args = args
        self._init_kwargs = kwargs

    def __repr__(self):
        return f"<DummyClient args={self._init_args!r} kwargs={self._init_kwargs!r}>"


@pytest.mark.asyncio
async def test_connect_to_db_passes_correct_parameters(monkeypatch, tmp_path):
    fake_cert = tmp_path / "fake_cert.pem"
    fake_cert.write_text("dummy")
    monkeypatch.setattr(db_module, "MongoClient", DummyClient)
    monkeypatch.setattr(db_module, "CERT_PATH", fake_cert)

    fake_uri = "mongodb://test-host:27017"

    client = await connect_to_db(fake_uri)

    assert isinstance(client, DummyClient)
    assert client._init_args == (fake_uri,)
    kw = client._init_kwargs
    assert kw["tls"] is True
    assert kw["tlsCertificateKeyFile"] == str(fake_cert)
    assert kw["tlsCAFile"] == certifi.where()
    assert isinstance(kw["server_api"], ServerApi)
    assert kw["server_api"].version == "1"
    assert kw["serverSelectionTimeoutMS"] == 5000


@pytest.mark.asyncio
async def test_connect_to_db_returns_new_client_each_time(monkeypatch):
    monkeypatch.setattr(db_module, "MongoClient", DummyClient)

    c1 = await connect_to_db("uri1")
    c2 = await connect_to_db("uri2")

    assert isinstance(c1, DummyClient)
    assert isinstance(c2, DummyClient)
    assert c1 is not c2












# tests/test_utility.py
import os
import jwt
import pytest
from datetime import datetime, timezone, timedelta
from bson import ObjectId

import app.utility.utility as util  # adjust if your file lives elsewhere

# -----------------------------------------------------------------------------
# Helpers & fixtures
# -----------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_env_and_connect(monkeypatch):
    """
    - Force LIVING_TIME to a known small number for generate_jwt.
    - Monkey-patch connect_to_db so it never touches a real Mongo.
    """
    # make token expire in 2 minutes
    monkeypatch.setattr(util, "LIVING_TIME", "2")

    class FakeCollection:
        def __init__(self, docs):
            # accept list or single dict
            self._docs = docs if isinstance(docs, list) else [docs]

        def find_one(self, query):
            for doc in self._docs:
                # match by _id field
                if all(doc.get(k) == v for k, v in query.items()):
                    return doc
            return None

        def find(self, _):
            # return an iterator
            return iter(self._docs)

    class FakeDB:
        def __init__(self, users=None):
            # Allow passing in a pre-seeded users list
            self._users = users or []

        def get_collection(self, name):
            if name == "users":
                return FakeCollection(self._users)
            raise RuntimeError(f"Unexpected collection: {name}")

    class FakeClient:
        def __init__(self, db):
            self._db = db

        def get_database(self, name):
            assert name == "website"
            return self._db

    # a sample user to seed into user_details/get_all_users
    sample_id = ObjectId()
    sample_user = {
        "_id": sample_id,
        "email": "foo@bar.com",
        "other": "value",
    }

    fake_db = FakeDB(users=[sample_user])
    fake_client = FakeClient(fake_db)

    async def fake_connect(uri):
        assert uri == util.MONGO_URI
        return fake_client

    monkeypatch.setattr(util, "connect_to_db", fake_connect)

    yield
    # teardown if needed


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

def test_generate_jwt_payload_and_expiration():
    # generate token
    token = util.generate_jwt(user_id="12345", email="a@b.com")

    # decode without verifying exp
    decoded = jwt.decode(token, util.SECRET_KEY, algorithms=[util.ALGORITHM], options={"verify_exp": False})
    assert decoded["user_id"] == "12345"
    assert decoded["email"] == "a@b.com"

    # check exp is ~ now + 2 minutes
    now = datetime.now(timezone.utc)
    exp = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
    delta = exp - now
    # allow a few seconds of jitter
    assert timedelta(minutes=1, seconds=50) < delta < timedelta(minutes=2, seconds=10)


@pytest.mark.asyncio
async def test_user_details_found():
    # we seeded one user with _id == sample_id in the fixture
    sample_id = util.user_details.__defaults__[0] if False else None
    # but better to retrieve it directly from the fake DB in fixture
    all_users = await util.get_all_users()
    sample = all_users[0]
    sid = str(sample["_id"])

    user = await util.user_details(sid)
    assert user is not None
    assert user["email"] == "foo@bar.com"
    assert isinstance(user["_id"], ObjectId)


@pytest.mark.asyncio
async def test_user_details_not_found():
    # generate a random ObjectId not in fake DB
    fake_id = str(ObjectId())
    user = await util.user_details(fake_id)
    assert user is None


@pytest.mark.asyncio
async def test_get_all_users_returns_list_of_dicts():
    users = await util.get_all_users()
    assert isinstance(users, list)
    assert len(users) == 1
    u = users[0]
    assert u["email"] == "foo@bar.com"
    assert isinstance(u["_id"], ObjectId)


@pytest.mark.asyncio
async def test_access_collection_returns_collection_object(monkeypatch):
    # create a different fake client that returns a custom collection
    class DummyColl: pass
    class DummyDB:
        def get_collection(self, name):
            return DummyColl()

    class DummyClient:
        def get_database(self, name):
            return DummyDB()

    async def fake_connect(uri):
        return DummyClient()

    monkeypatch.setattr(util, "connect_to_db", fake_connect)

    coll = await util.access_collection("whatever")
    assert isinstance(coll, DummyColl)

