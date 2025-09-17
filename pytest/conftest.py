import os, pathlib, sys, pytest
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("ENV", "ci")

from dossier_hr_backend import app

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
