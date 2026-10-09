"""
Unit tests for authentication module.
"""

import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from unittest.mock import Mock

from chacc_authentication.module.auth import (
    get_password_hash,
    verify_password,
    authenticate_user,
    create_access_token,
)
from chacc_authentication.module.models import User, UserCreate
from chacc_authentication.module.context_factory import set_module_context


class MockBackboneContext:
    """Mock BackboneContext for testing purposes."""

    def __init__(self):
        self.logger = Mock()
        self._module_config = {"SECRET_KEY": "test-secret-key-for-testing-purposes"}
        self._db_session = None

    def get_module_config(self, key, module, default=None):
        """Get module configuration."""
        if module == "authentication" and key == "SECRET_KEY":
            return self._module_config.get(key, default)
        return default

    def get_db(self):
        """Get database session (mocked as async generator)."""

        async def mock_db_generator():
            if self._db_session is None:
                from sqlalchemy.orm import sessionmaker
                from sqlalchemy import create_engine

                engine = create_engine("sqlite:///:memory:")
                User.__table__.create(engine, checkfirst=True)
                SessionLocal = sessionmaker(
                    autocommit=False, autoflush=False, bind=engine
                )
                self._db_session = SessionLocal()
            try:
                yield self._db_session
            finally:
                pass

        return mock_db_generator()

    def set_db_session(self, session):
        """Set the database session to be returned by get_db()."""
        self._db_session = session


@pytest.fixture
def mock_context():
    """Create a mock BackboneContext for testing."""
    context = MockBackboneContext()
    set_module_context(context)
    yield context
    set_module_context(None)


@pytest.fixture
def db_session():
    """Database session fixture for testing."""
    engine = create_engine("sqlite:///:memory:")
    User.__table__.create(engine, checkfirst=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        User.__table__.drop(engine, checkfirst=True)


def test_password_hashing():
    """Test password hashing and verification."""
    password = "testpassword"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed)
    assert not verify_password("wrongpassword", hashed)


def test_create_access_token(mock_context):
    """Test JWT token creation."""
    mock_context._module_config["SECRET_KEY"] = "test-secret-key"

    data = {"sub": "testuser"}
    token = create_access_token(data)
    assert isinstance(token, str)
    assert len(token) > 0


@pytest_asyncio.fixture
async def async_db_session():
    """Async database session fixture — authenticate_user() is async and needs one."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(User.metadata.create_all)
    AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_authenticate_user(async_db_session):
    """Test user authentication."""
    password = "testpass"
    hashed = get_password_hash(password)
    user = User(username="testuser", email="test@example.com", password_hash=hashed)
    async_db_session.add(user)
    await async_db_session.commit()

    auth_user = await authenticate_user(async_db_session, "testuser", password)
    assert auth_user is not False
    assert auth_user.username == "testuser"

    auth_user = await authenticate_user(async_db_session, "testuser", "wrongpass")
    assert auth_user is False

    # Test non-existent user
    auth_user = await authenticate_user(async_db_session, "nonexistent", password)
    assert auth_user is False


def test_user_model():
    """Test User model creation."""
    user = User(username="test", email="test@example.com", password_hash="hash")
    assert user.username == "test"
    assert user.email == "test@example.com"
    assert User.is_active.default.arg is True


def test_user_model_with_persistence(db_session):
    """Test User model creation with persistence to get default values."""
    user = User(username="test", email="test@example.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.username == "test"
    assert user.email == "test@example.com"
    assert user.is_active is True


def test_user_create_model():
    """Test UserCreate Pydantic model."""
    user_data = UserCreate(
        username="test", email="test@example.com", password="pass", passwordConfirm="pass"
    )
    assert user_data.username == "test"
    assert user_data.email == "test@example.com"
    assert user_data.password == "pass"


def test_authentication_module_info():
    """Test module information retrieval."""
    from chacc_authentication.module.main import get_plugin_info

    info = get_plugin_info()
    assert info["name"] == "authentication"
    assert info["version"] == "0.1.0"
    assert "status" in info


async def run_module_tests():
    """
    Run all module tests.
    This function is called by the ChaCC backbone when the module is loaded.
    """
    import sys
    import os

    module_dir = os.path.dirname(os.path.dirname(__file__))
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)

    try:
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                __file__,
                "-v",
                "--tb=short",
                "--no-header",
            ],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(__file__),
        )

        if result.returncode == 0:
            print(f"✓ All authentication tests passed")
            return {"status": "passed", "message": f"All authentication tests passed"}
        else:
            print(f"✗ authentication tests failed")
            if result.stdout:
                print("Test output:")
                print(result.stdout)
            if result.stderr:
                print("Errors:")
                print(result.stderr)
            return {
                "status": "failed",
                "message": f"authentication tests failed",
                "details": result.stdout + result.stderr,
            }

    except Exception as e:
        print(f"✗ Error running authentication tests: {e}")
        return {
            "status": "error",
            "message": f"Error running authentication tests: {e}",
        }