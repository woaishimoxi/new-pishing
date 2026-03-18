"""
Test Configuration
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def app():
    """Create application for testing"""
    from app import create_app
    from app.core import reset_config
    
    reset_config()
    app = create_app()
    app.config['TESTING'] = True
    
    yield app
    
    reset_config()


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test runner"""
    return app.test_cli_runner()


@pytest.fixture
def tmp_path(tmp_path):
    """Create temporary directory for test files"""
    return tmp_path
