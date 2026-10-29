from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture(scope="session")
def client():
    # Never call the real Groq API from tests, whatever is in .env.
    import os

    os.environ["GROQ_API_KEY"] = "your_groq_api_key_here"
    os.environ["MODEL_DIR"] = str(FIXTURES / "no-model-here")
    from app.config import get_settings

    get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()
