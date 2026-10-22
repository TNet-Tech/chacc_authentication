from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from chacc_api import BackboneContext
from typing import Optional

from chacc_authentication.module.models import User, UserCreate, UserLogin, Token, UserResponse, OAuthSession
from chacc_authentication.module.models.request_models import TokenRefreshRequest, RevokeRequest
from chacc_authentication.module.auth import (
    get_current_user,
    get_current_user_required,
    authenticate_user,
    get_password_hash,
)
from chacc_authentication.module.context_factory import get_module_context, get_db, get_async_db
from chacc_authentication.module.services import (
    login_user,
    refresh_token,
    revoke_token,
    logout_all_sessions,
    get_rbac_service,
)
from chacc_authentication.module.dependencies import get_redis_client
from pydantic import BaseModel
from fastapi import Query
from sqlalchemy import func, or_, select
from math import ceil
from typing import List

router = APIRouter()

registerRouter = APIRouter()


class PaginatedUsers(BaseModel):
    data: List[UserResponse]
    total: int
    page: int
    size: int
    pages: int


class UserAdminUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


class UserSelfUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    password: Optional[str] = None
    passwordConfirm: Optional[str] = None


async def _require_write_users(current_user: User, db: Session) -> None:
    """Guard admin user-management endpoints behind WRITE_USERS."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)
    if not await rbac.has_privilege(current_user.id, "WRITE_USERS"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USERS",
        )


@registerRouter.post("/register", response_model=UserResponse)
async def register(
    user: UserCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: Optional[UserResponse] = Depends(get_current_user),
):
    from sqlalchemy import select, or_
    result = await db.execute(
        select(User).where(
            (User.username == user.username) | (User.email == user.email)
        )
    )
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(
            status_code=400, detail="Username or email already registered"
        )

    if user.password != user.passwordConfirm:
        raise HTTPException(status_code=400, detail="Passwords should match")

    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return UserResponse(
        uuid=str(db_user.uuid),
        username=db_user.username,
        first_name=db_user.first_name,
        middle_name=db_user.middle_name,
        last_name=db_user.last_name,
        email=db_user.email,
        is_active=db_user.is_active,
    )


@router.post("/login", response_model=Token)
async def login(user: UserLogin, request: Request, db: AsyncSession = Depends(get_async_db)):
    db_user = await authenticate_user(db, user.username, user.password)
    if not db_user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    context = get_module_context()
    return await login_user(db, db_user, request, context)


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user_required())):
    return UserResponse(
        uuid=str(current_user.uuid),
        username=current_user.username,
        first_name=current_user.first_name,
        middle_name=current_user.middle_name,
        last_name=current_user.last_name,
        email=current_user.email,
        is_active=current_user.is_active,
    )


@router.put("/me", response_model=UserResponse)
async def update_user_me(
    user_update: UserSelfUpdate,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    if user_update.password or user_update.passwordConfirm:
        if user_update.password != user_update.passwordConfirm:
            raise HTTPException(status_code=400, detail="Passwords should match")

    from sqlalchemy import select
    result = await db.execute(select(User).where(User.uuid == current_user.uuid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.username is not None and user_update.username != user.username:
        existing = await db.execute(
            select(User).where(User.username == user_update.username, User.uuid != user.uuid)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already registered")
        user.username = user_update.username

    if user_update.email is not None and user_update.email != user.email:
        existing = await db.execute(
            select(User).where(User.email == user_update.email, User.uuid != user.uuid)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already registered")
        user.email = user_update.email

    if user_update.first_name is not None:
        user.first_name = user_update.first_name
    if user_update.last_name is not None:
        user.last_name = user_update.last_name
    if user_update.password:
        user.password_hash = get_password_hash(user_update.password)

    await db.commit()
    await db.refresh(user)
    return UserResponse(
        uuid=str(user.uuid),
        username=user.username,
        first_name=user.first_name,
        middle_name=user.middle_name,
        last_name=user.last_name,
        email=user.email,
        is_active=user.is_active,
    )


@router.delete("/me")
async def delete_user_me(
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    from sqlalchemy import delete, select
    result = await db.execute(select(User).where(User.uuid == current_user.uuid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.execute(delete(OAuthSession).where(OAuthSession.user_id == user.id))
    await db.delete(user)
    await db.commit()
    return {"message": "User deleted"}


@router.get("/users", response_model=PaginatedUsers)
async def read_users(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    search: str = Query(""),
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """List users (server-side pagination + search)."""
    stmt = select(User)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            or_(
                User.username.ilike(like),
                User.email.ilike(like),
                User.first_name.ilike(like),
                User.last_name.ilike(like),
            )
        )
    count_result = await db.execute(select(func.count()).select_from(stmt.subquery()))
    total = count_result.scalar_one()
    result = await db.execute(stmt.order_by(User.username).offset((page - 1) * size).limit(size))
    users = result.scalars().all()
    data = [
        UserResponse(
            uuid=str(u.uuid),
            username=u.username,
            first_name=u.first_name,
            middle_name=u.middle_name,
            last_name=u.last_name,
            email=u.email,
            is_active=u.is_active,
        )
        for u in users
    ]
    return PaginatedUsers(
        data=data,
        total=total,
        page=page,
        size=size,
        pages=max(1, ceil(total / size)) if size else 1,
    )


@router.put("/users/{user_uuid}", response_model=UserResponse)
async def admin_update_user(
    user_uuid: str,
    payload: UserAdminUpdate,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Update any user (admin). Requires WRITE_USERS."""
    await _require_write_users(current_user, db)

    from sqlalchemy import select
    result = await db.execute(select(User).filter(User.uuid == user_uuid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.username is not None:
        user.username = payload.username
    if payload.email is not None:
        user.email = payload.email
    if payload.first_name is not None:
        user.first_name = payload.first_name
    if payload.last_name is not None:
        user.last_name = payload.last_name
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password:
        user.password_hash = get_password_hash(payload.password)

    await db.commit()
    await db.refresh(user)
    return UserResponse(
        uuid=str(user.uuid),
        username=user.username,
        first_name=user.first_name,
        middle_name=user.middle_name,
        last_name=user.last_name,
        email=user.email,
        is_active=user.is_active,
    )


@router.delete("/users/{user_uuid}")
async def admin_delete_user(
    user_uuid: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Delete any user (admin). Requires WRITE_USERS."""
    await _require_write_users(current_user, db)

    from sqlalchemy import select, delete
    result = await db.execute(select(User).filter(User.uuid == user_uuid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    # Remove dependent login sessions first (FK is NOT NULL, no DB cascade).
    await db.execute(delete(OAuthSession).where(OAuthSession.user_id == user.id))
    await db.delete(user)
    await db.commit()
    return {"success": True, "message": "User deleted"}


@router.post("/refresh", response_model=Token)
async def refresh_token_endpoint(
    token_request: TokenRefreshRequest, request: Request, db: AsyncSession = Depends(get_async_db)
):
    """Refresh access token using a valid refresh token."""
    context = get_module_context()

    token = await refresh_token(db, token_request, request, context)

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    return token


@router.post("/revoke")
async def revoke_token_endpoint(
    revoke_request: RevokeRequest, db: AsyncSession = Depends(get_async_db)
):
    """Revoke a refresh token (logout from specific device/session)."""
    context = get_module_context()

    success = await revoke_token(db, revoke_request, context)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
        )

    return {"message": "Token revoked successfully"}


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Logout current user from all devices (revoke all sessions)."""
    context = get_module_context()

    count = await logout_all_sessions(db, current_user.id, context)

    return {"message": f"Logged out from {count} session(s)"}
