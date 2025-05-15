from pymongo import MongoClient
from pymongo.server_api import ServerApi
import certifi


async def connect_to_db(uri: str):
    client = MongoClient(
        uri,
        tls=True,
        tlsCertificateKeyFile="../cert.pem",
        tlsCAFile=certifi.where(),           
        server_api=ServerApi("1"),
        serverSelectionTimeoutMS=5000
    )
    return client

