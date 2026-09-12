from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Request
from chacc_api import BackboneContext, RedisService

from chacc_authentication.module.auth import get_password_hash
from chacc_authentication.module.models import User, Token, TokenRefreshRequest, RevokeRequest
from chacc_authentication.module.services.oauth2_service import OAuth2Service
from chacc_authentication.module.context_factory import get_module_context
from datetime import timedelta, datetime, timezone
from sqlalchemy import select, func


async def create_default_user(context):
    """
    Create a default admin user if no users exist.
    Uses environment variables for configuration:
    - DEFAULT_ADMIN_USERNAME: Default admin username (default: "admin")
    - DEFAULT_ADMIN_PASSWORD: Default admin password (default: "admin123")
    """
    _module_context = context if context else get_module_context()

    default_username = _module_context.get_module_config(
        "DEFAULT_ADMIN_USERNAME", "authentication", "admin"
    )
    default_password = _module_context.get_module_config(
        "DEFAULT_ADMIN_PASSWORD", "authentication", "admin123"
    )

    db_gen = _module_context.get_db_async()
    db = await anext(db_gen)
    try:
        result = await db.execute(select(func.count()).select_from(User))
        user_count = result.scalar() or 0
        if user_count > 0:
            _module_context.logger.info(
                f"Users already exist ({user_count}), skipping default user creation"
            )
            return

        hashed_password = get_password_hash(default_password)
        default_user = User(
            username=default_username,
            email=f"{default_username}@chacc.local",
            password_hash=hashed_password,
            is_active=True,
        )

        db.add(default_user)
        await db.commit()
        await db.refresh(default_user)

        _module_context.logger.info(f"Created default admin user: {default_username}")
        _module_context.logger.warning(
            "DEFAULT CREDENTIALS - Please change the default password in production!"
        )
    finally:
        await db_gen.aclose()


async def ensure_default_admin_privileges(context):
    """Guarantee the default admin holds the ALL super-privilege.

    Runs on every startup (idempotent) so the RBAC system is always
    bootstrappable — without a super-admin, nobody could grant privileges or
    roles, locking the whole access-management surface.
    """
    from chacc_authentication.module.services.rbac_service import get_rbac_service

    _module_context = context if context else get_module_context()
    default_username = _module_context.get_module_config(
        "DEFAULT_ADMIN_USERNAME", "authentication", "admin"
    )

    db_gen = _module_context.get_db_async()
    db = await anext(db_gen)
    try:
        from sqlalchemy import select
        result = await db.execute(select(User).filter(User.username == default_username))
        admin = result.scalar_one_or_none()
        if not admin:
            return

        rbac = get_rbac_service(db)
        if not await rbac.has_privilege(admin.id, "ALL"):
            await rbac.assign_direct_privilege_to_user(admin.id, "ALL")
            _module_context.logger.info(
                f"Granted ALL privilege to default admin '{default_username}'"
            )
    finally:
        await db_gen.aclose()


async def get_token_expiry_settings(context):
    """Get token expiry settings from module config."""
    access_token_expire_minutes = int(
        context.get_module_config("ACCESS_TOKEN_EXPIRE_MINUTES", "authentication", 10)
    )
    refresh_token_expire_minutes = int(
        context.get_module_config("REFRESH_TOKEN_EXPIRE_MINUTES", "authentication", 15)
    )
    return access_token_expire_minutes, refresh_token_expire_minutes


async def login_user(
    db: Session, user: User, request: Request, context: BackboneContext
) -> Token:
    """
    Authenticate user and create OAuth2 session.
    Returns Token with access and refresh tokens.
    """
    redis_service: RedisService = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()

    access_token_expire_minutes, refresh_token_expire_minutes = (
        await get_token_expiry_settings(context)
    )

    ip_address = request.client.host if request.client else None
    device_info = request.headers.get("user-agent", "Unknown")

    oauth_service = OAuth2Service(db, redis_client)
    expires_delta = timedelta(minutes=access_token_expire_minutes)
    expires_at = datetime.now(timezone.utc) + expires_delta

    access_token, refresh_token, session_uuid = await oauth_service.create_session(
        user=user,
        expires_delta=expires_delta,
        device_info=device_info,
        ip_address=ip_address,
    )

    refresh_token_expiry = refresh_token_expire_minutes * 60

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        access_token_expires_at=expires_at.isoformat(),
        access_token_expiry=access_token_expire_minutes * 60,
        refresh_token_expiry=refresh_token_expiry,
    )


async def refresh_token(
    db: Session,
    token_request: TokenRefreshRequest,
    request: Request,
    context: BackboneContext,
) -> Token:
    """
    Refresh access token using a valid refresh token.
    Returns new Token with rotated tokens.
    """
    redis_service = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()

    access_token_expire_minutes, refresh_token_expire_minutes = (
        await get_token_expiry_settings(context)
    )

    ip_address = request.client.host if request.client else None
    device_info = request.headers.get("user-agent", "Unknown")

    oauth_service = OAuth2Service(db, redis_client)
    expires_delta = timedelta(minutes=access_token_expire_minutes)

    result = await oauth_service.rotate_session(
        old_refresh_token=token_request.refresh_token,
        new_expires_delta=expires_delta,
        device_info=device_info,
        ip_address=ip_address,
    )

    if result is None:
        return None

    expires_at = datetime.now(timezone.utc) + expires_delta
    access_token, refresh_token, session_uuid = result

    refresh_token_expiry = refresh_token_expire_minutes * 60

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=access_token_expire_minutes * 60,
        access_token_expires_at=expires_at.isoformat(),
        access_token_expiry=access_token_expire_minutes * 60,
        refresh_token_expiry=refresh_token_expiry,
    )


async def revoke_token(db: AsyncSession, revoke_request: RevokeRequest, context) -> bool:
    """Revoke a refresh token (logout from specific device/session)."""
    redis_service = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()


    try:

        oauth_service = OAuth2Service(db, redis_client)
        return await oauth_service.revoke_session(revoke_request.refresh_token)
    finally:
        await db.close()


async def logout_all_sessions(db: Session, user_id: int, context) -> int:
    """Logout current user from all devices (revoke all sessions)."""
    redis_service = context.get_service("redis")
    redis_client = None
    if redis_service:
        redis_client = await redis_service.get_client()

    try:
        oauth_service = OAuth2Service(db, redis_client)
        return await oauth_service.revoke_all_user_sessions(user_id)
    finally:
        await db.close()