"""
Refresh sessions: they last as long as the refresh token, and an expired one
can't be rotated.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from chacc_authentication.module.context_factory import set_module_context
from chacc_authentication.module.models import User
from chacc_authentication.module.models.session import OAuthSession
from chacc_authentication.module.services.oauth2_service import OAuth2Service
from chacc_authentication.module.tests.test_module import MockBackboneContext

ACCESS = timedelta(minutes=10)
REFRESH = timedelta(minutes=15)


@pytest.fixture(autouse=True)
def context():
    set_module_context(MockBackboneContext())
    yield
    set_module_context(None)


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(User.metadata.create_all)
    async with sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def user(db):
    user = User(username="alice", email="alice@example.com", password_hash="x")
    db.add(user)
    await db.commit()
    return user


async def _session(db, refresh_token):
    token_id = refresh_token.removeprefix("refresh_")
    result = await db.execute(select(OAuthSession).filter(OAuthSession.refresh_token_id == token_id))
    return result.scalar_one()


def _utc(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _minutes_left(session):
    return (_utc(session.expires_at) - datetime.now(timezone.utc)).total_seconds() / 60


@pytest.mark.asyncio
async def test_session_lasts_as_long_as_the_refresh_token(db, user):
    service = OAuth2Service(db)
    _, refresh, _ = await service.create_session(user, expires_delta=ACCESS, refresh_expires_delta=REFRESH)

    assert 14 < _minutes_left(await _session(db, refresh)) <= 15


@pytest.mark.asyncio
async def test_without_a_refresh_lifetime_the_session_uses_the_access_lifetime(db, user):
    service = OAuth2Service(db)
    _, refresh, _ = await service.create_session(user, expires_delta=ACCESS)

    assert 9 < _minutes_left(await _session(db, refresh)) <= 10


@pytest.mark.asyncio
async def test_rotation_works_after_the_access_token_expired(db, user):
    """The console refreshes after a 401, when the access token has expired."""
    service = OAuth2Service(db)
    _, refresh, _ = await service.create_session(user, expires_delta=ACCESS, refresh_expires_delta=REFRESH)
    # 12 minutes later: past the access token, within the refresh token.
    session = await _session(db, refresh)
    await db.execute(
        update(OAuthSession)
        .where(OAuthSession.id == session.id)
        .values(expires_at=datetime.now(timezone.utc) + timedelta(minutes=3))
    )
    await db.commit()

    result = await service.rotate_session(
        refresh, new_expires_delta=ACCESS, new_refresh_expires_delta=REFRESH
    )

    assert result is not None
    assert 14 < _minutes_left(await _session(db, result[1])) <= 15


@pytest.mark.asyncio
async def test_an_expired_refresh_token_is_not_rotated(db, user):
    service = OAuth2Service(db)
    _, refresh, _ = await service.create_session(user, expires_delta=ACCESS, refresh_expires_delta=REFRESH)
    session = await _session(db, refresh)
    await db.execute(
        update(OAuthSession)
        .where(OAuthSession.id == session.id)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()

    assert await service.rotate_session(refresh, new_expires_delta=ACCESS) is None
    assert await service.verify_session(refresh) is None


@pytest.mark.asyncio
async def test_a_rotated_refresh_token_is_not_rotated_again(db, user):
    service = OAuth2Service(db)
    _, refresh, _ = await service.create_session(user, expires_delta=ACCESS, refresh_expires_delta=REFRESH)

    assert await service.rotate_session(refresh, new_expires_delta=ACCESS) is not None
    assert await service.rotate_session(refresh, new_expires_delta=ACCESS) is None
