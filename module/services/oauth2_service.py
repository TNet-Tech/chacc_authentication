"""
OAuth2 Service with Hybrid DB/Redis Fallback Strategy.

This service implements OAuth2 refresh token rotation with graceful degradation:
- Redis is used for high-speed session/token management and caching
- PostgreSQL is the ultimate source of truth for rotating refresh tokens
- If Redis is unavailable, the system seamlessly falls back to PostgreSQL

Flow:
1. Creation: Write to DB. Attempt Redis write (catch/ignore errors).
2. Verification: Attempt Redis read. If miss, query DB.
3. Rotation: Mark is_rotated=True in DB. Attempt Redis update/delete.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from chacc_authentication.module.models.session import OAuthSession
from chacc_authentication.module.models.user import User
from chacc_authentication.module.auth import create_access_token

logger = logging.getLogger(__name__)


def _expired(expires_at: datetime) -> bool:
    """Whether a session's expiry has passed. Stored times without a zone are UTC."""
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


class OAuth2Service:
    """
    OAuth2 Service with Hybrid DB/Redis Fallback.

    Redis is used as a fast cache layer, but the DB always has the final say.
    """

    def __init__(self, db: AsyncSession, redis_client=None):
        self.db = db
        self.redis = redis_client

    def _get_redis_client(self):
        """Get Redis client if available."""
        return self.redis

    async def create_session(
        self,
        user: User,
        expires_delta: timedelta = timedelta(minutes=30),
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ) -> tuple[str, str, str]:
        """
        Create a new OAuth2 session with refresh token.

        expires_delta is the access token's lifetime; refresh_expires_delta is
        the session's (the refresh token's), and defaults to expires_delta.

        Returns:
            tuple: (access_token, refresh_token, session_uuid)
        """
        access_token = create_access_token(
            data={"sub": user.username, "type": "access"}, expires_delta=expires_delta
        )

        refresh_token_id = str(uuid.uuid4())
        family_id = str(uuid.uuid4())
        session_delta = refresh_expires_delta or expires_delta
        expires_at = datetime.now(timezone.utc) + session_delta

        oauth_session = OAuthSession(
            user_id=user.id,
            family_id=family_id,
            refresh_token_id=refresh_token_id,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )

        self.db.add(oauth_session)
        await self.db.commit()
        await self.db.refresh(oauth_session)

        redis_client = self._get_redis_client()
        if redis_client:
            try:
                cache_data = {
                    "user_id": user.id,
                    "family_id": family_id,
                    "is_rotated": False,
                    "expires_at": expires_at.isoformat(),
                }
                await redis_client.setex(
                    f"refresh_token:{refresh_token_id}",
                    int(session_delta.total_seconds()),
                    json.dumps(cache_data),
                )
            except Exception as e:
                logger.warning(
                    f"Redis unavailable for session creation, using DB only: {e}"
                )

        refresh_token = f"refresh_{refresh_token_id}"

        return access_token, refresh_token, str(oauth_session.uuid)

    async def verify_session(self, refresh_token: str) -> Optional[OAuthSession]:
        """
        Verify a refresh token and return the session.

        Flow:
        1. Try Redis first
        2. If Redis miss, query DB
        """
        if not refresh_token.startswith("refresh_"):
            return None

        refresh_token_id = refresh_token.replace("refresh_", "")

        redis_client = self._get_redis_client()

        if redis_client:
            try:
                cached = await redis_client.get(f"refresh_token:{refresh_token_id}")
                if cached:
                    cache_data = json.loads(cached)
                    if cache_data.get("is_rotated", False):
                        return None
                    result = await self.db.execute(
                        select(OAuthSession).filter(OAuthSession.refresh_token_id == refresh_token_id)
                    )
                    session = result.scalar_one_or_none()
                    if session and not _expired(session.expires_at):
                        return session
            except Exception as e:
                logger.warning(
                    f"Redis unavailable for session verification, falling back to DB: {e}"
                )

        result = await self.db.execute(
            select(OAuthSession).filter(OAuthSession.refresh_token_id == refresh_token_id)
        )
        session = result.scalar_one_or_none()

        if not session:
            return None

        if session.is_rotated or _expired(session.expires_at):
            return None

        return session

    async def rotate_session(
        self,
        old_refresh_token: str,
        new_expires_delta: timedelta = timedelta(minutes=30),
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        new_refresh_expires_delta: Optional[timedelta] = None,
    ) -> Optional[tuple[str, str, str]]:
        """
        Rotate a refresh token.

        Marks old token as rotated in DB and creates a new session. An expired
        token isn't rotated.
        DB is the source of truth - Redis cache cleanup is attempted but not required.

        Returns:
            tuple: (new_access_token, new_refresh_token, new_session_uuid) or None if invalid
        """
        if not old_refresh_token.startswith("refresh_"):
            return None

        old_token_id = old_refresh_token.replace("refresh_", "")

        result = await self.db.execute(
            select(OAuthSession).filter(OAuthSession.refresh_token_id == old_token_id)
        )
        old_session = result.scalar_one_or_none()

        if not old_session or old_session.is_rotated or _expired(old_session.expires_at):
            return None

        old_session.is_rotated = True
        await self.db.commit()
        logger.info(f"Rotated session in database: {old_token_id}")

        result = await self.db.execute(
            select(User).filter(User.id == old_session.user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            return None

        new_tokens = await self.create_session(
            user=user,
            expires_delta=new_expires_delta,
            device_info=device_info,
            ip_address=ip_address,
            refresh_expires_delta=new_refresh_expires_delta,
        )

        redis_client = self._get_redis_client()
        if redis_client:
            try:
                await redis_client.delete(f"refresh_token:{old_token_id}")
            except Exception as e:
                logger.warning(
                    f"Redis unavailable for rotation cleanup, DB is source of truth: {e}"
                )

        return new_tokens

    async def revoke_session(self, refresh_token: str) -> bool:
        """
        Revoke a session (logout).

        Marks session as rotated in DB. Redis cleanup is attempted but not required.
        """
        if not refresh_token.startswith("refresh_"):
            return False

        refresh_token_id = refresh_token.replace("refresh_", "")

        result = await self.db.execute(
            select(OAuthSession).filter(OAuthSession.refresh_token_id == refresh_token_id)
        )
        session = result.scalar_one_or_none()

        if session:
            session.is_rotated = True
            await self.db.commit()
            logger.info(f"Revoked session in database: {refresh_token_id}")

            redis_client = self._get_redis_client()
            if redis_client:
                try:
                    await redis_client.delete(f"refresh_token:{refresh_token_id}")
                except Exception as e:
                    logger.warning(
                        f"Redis unavailable for revocation cleanup, DB is source of truth: {e}"
                    )

            return True

        return False

    async def revoke_all_user_sessions(self, user_id: int) -> int:
        """
        Revoke all sessions for a user.

        Returns:
            Number of sessions revoked
        """
        result = await self.db.execute(
            select(OAuthSession).filter(
                OAuthSession.user_id == user_id, OAuthSession.is_rotated == False
            )
        )
        sessions = result.scalars().all()

        count = 0
        redis_client = self._get_redis_client()

        for session in sessions:
            session.is_rotated = True
            count += 1

            if redis_client:
                try:
                    await redis_client.delete(
                        f"refresh_token:{session.refresh_token_id}"
                    )
                except Exception as e:
                    logger.warning(f"Redis unavailable for session cleanup: {e}")

        if count > 0:
            await self.db.commit()
            logger.info(f"Revoked {count} sessions in database for user {user_id}")

        return count


def get_oauth2_service(db: AsyncSession, redis_client=None) -> OAuth2Service:
    """Create an OAuth2Service instance."""
    return OAuth2Service(db, redis_client)
