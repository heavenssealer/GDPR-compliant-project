from pymongo import MongoClient
from pymongo.server_api import ServerApi
import certifi

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/app/… → project root
CERT_PATH = BASE_DIR / "cert.pem"

async def connect_to_db(uri: str):
    client = MongoClient(
        uri,
        tls=True,
        tlsCertificateKeyFile=str(CERT_PATH),
        tlsCAFile=certifi.where(),           
        server_api=ServerApi("1"),
        serverSelectionTimeoutMS=5000
    )
    return client

