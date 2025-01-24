import pytest
import requests

# Base URL for the application
BASE_URL = 'http://localhost:80'

# Pytest fixtures and utility functions
@pytest.fixture
def session():
    return requests.Session()
