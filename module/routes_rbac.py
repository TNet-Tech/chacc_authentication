"""
RBAC Routes for privilege and role management.

This module provides API endpoints for:
- Privilege management (CRUD)
- Role management (CRUD)
- User role assignment
- User direct privilege assignment
"""

from math import ceil
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from chacc_api import BackboneContext
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import joinedload, selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from chacc_authentication.module.auth import get_current_user, get_current_user_required
from chacc_authentication.module.context_factory import get_db, get_async_db, get_module_context
from chacc_authentication.module.models import User, Privilege, Role, RoleGroup
from chacc_authentication.module.services import get_rbac_service
from chacc_authentication.module.dependencies import get_redis_client

router = APIRouter(prefix="/rbac")


# Pydantic models for request/response
class PrivilegeResponse(BaseModel):
    id: int
    name: str
    description: str
    severity: str

    class Config:
        from_attributes = True


class RoleResponse(BaseModel):
    id: int
    name: str
    description: str
    is_system: bool

    class Config:
        from_attributes = True


class RoleWithPrivilegesResponse(BaseModel):
    id: int
    name: str
    description: str
    is_system: bool
    privileges: List[PrivilegeResponse]

    class Config:
        from_attributes = True


class PaginatedPrivileges(BaseModel):
    data: List[PrivilegeResponse]
    total: int
    page: int
    size: int
    pages: int


class PaginatedRoles(BaseModel):
    data: List[RoleWithPrivilegesResponse]
    total: int
    page: int
    size: int
    pages: int


def _page_meta(total: int, page: int, size: int) -> dict:
    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": max(1, ceil(total / size)) if size else 1,
    }


class UserPrivilegesResponse(BaseModel):
    user_uuid: str
    privileges: List[str]


class UserRolesResponse(BaseModel):
    user_uuid: str
    roles: List[str]


class PrivilegeCreate(BaseModel):
    name: str
    description: str
    severity: str  # CRITICAL, VERY HIGH, HIGH, MEDIUM, LOW


class PrivilegeUpdate(BaseModel):
    description: Optional[str] = None
    severity: Optional[str] = None  # CRITICAL, VERY HIGH, HIGH, MEDIUM, LOW


class RoleCreate(BaseModel):
    name: str
    description: str


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    privileges: Optional[List[str]] = None  # replaces the full privilege set


class AssignPrivilegeRequest(BaseModel):
    privilege_name: str


class AssignRoleRequest(BaseModel):
    role_name: str


# ==================== Privilege Endpoints ====================


@router.get("/privileges", response_model=PaginatedPrivileges)
async def get_privileges(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    search: str = Query(""),
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """List privileges (server-side pagination + search)."""
    stmt = select(Privilege)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            or_(
                Privilege.name.ilike(like),
                Privilege.description.ilike(like),
                Privilege.severity.ilike(like),
            )
        )
    count_result = await db.execute(
        select(func.count()).select_from(stmt.subquery())
    )
    total = count_result.scalar_one()
    result = await db.execute(
        stmt.order_by(Privilege.name).offset((page - 1) * size).limit(size)
    )
    rows = result.scalars().all()
    return PaginatedPrivileges(data=rows, **_page_meta(total, page, size))


@router.post("/privileges", response_model=PrivilegeResponse)
async def create_privilege(
    privilege: PrivilegeCreate,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new privilege."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_PRIVILEGES",
        )

    # Check if privilege already exists
    existing = await rbac.get_privilege_by_name(privilege.name)
    if existing:
        raise HTTPException(
            status_code=400, detail=f"Privilege '{privilege.name}' already exists"
        )

    new_privilege = await rbac.create_privilege(
        name=privilege.name,
        description=privilege.description,
        severity=privilege.severity,
    )

    return new_privilege


@router.put("/privileges/{privilege_name}", response_model=PrivilegeResponse)
async def update_privilege(
    privilege_name: str,
    privilege: PrivilegeUpdate,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Update a privilege's description and/or severity."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_PRIVILEGES",
        )

    updated = await rbac.update_privilege(
        name=privilege_name,
        description=privilege.description,
        severity=privilege.severity,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Privilege not found")
    return updated


@router.delete("/privileges/{privilege_name}")
async def delete_privilege(
    privilege_name: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Delete a privilege by name."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_PRIVILEGES",
        )

    deleted = await rbac.delete_privilege(privilege_name)
    if not deleted:
        raise HTTPException(status_code=404, detail="Privilege not found")
    return {"success": True, "message": f"Privilege '{privilege_name}' deleted"}


# ==================== Role Endpoints ====================


@router.get("/roles", response_model=PaginatedRoles)
async def get_roles(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    search: str = Query(""),
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """List roles with privileges (server-side pagination + search)."""
    stmt = select(Role).options(selectinload(Role.privileges))
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            or_(Role.name.ilike(like), Role.description.ilike(like))
        )
    count_result = await db.execute(
        select(func.count()).select_from(stmt.subquery())
    )
    total = count_result.scalar_one()
    result = await db.execute(stmt.order_by(Role.name).offset((page - 1) * size).limit(size))
    rows = result.scalars().all()
    return PaginatedRoles(data=rows, **_page_meta(total, page, size))


@router.get("/roles/{role_name}", response_model=RoleWithPrivilegesResponse)
async def get_role(
    role_name: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Get a specific role with its privileges."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    role = await rbac.get_role_by_name(role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    return role


@router.post("/roles", response_model=RoleResponse)
async def create_role(
    role: RoleCreate,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new role."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES",
        )

    # Check if role already exists
    existing = await rbac.get_role_by_name(role.name)
    if existing:
        raise HTTPException(
            status_code=400, detail=f"Role '{role.name}' already exists"
        )

    new_role = await rbac.create_role(name=role.name, description=role.description)

    return new_role


@router.put("/roles/{role_name}", response_model=RoleWithPrivilegesResponse)
async def update_role(
    role_name: str,
    role: RoleUpdate,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Update a role's name, description and/or assigned privileges."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES",
        )

    try:
        updated = await rbac.update_role(
            role_name,
            description=role.description,
            new_name=role.name,
            privilege_names=role.privileges,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return updated


@router.delete("/roles/{role_name}")
async def delete_role(
    role_name: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Delete a non-system role."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES",
        )

    try:
        deleted = await rbac.delete_role(role_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="Role not found")
    return {"success": True, "message": f"Role '{role_name}' deleted"}


@router.put("/roles/{role_name}/privileges")
async def assign_privilege_to_role(
    role_name: str,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Assign a privilege to a role."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES",
        )

    success = await rbac.assign_privilege_to_role(role_name, request.privilege_name)
    if not success:
        raise HTTPException(status_code=404, detail="Role or privilege not found")

    return {
        "message": f"Privilege '{request.privilege_name}' assigned to role '{role_name}'"
    }


@router.delete("/roles/{role_name}/privileges")
async def remove_privilege_from_role(
    role_name: str,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Remove a privilege from a role."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    # Check if user has permission
    if not await rbac.has_privilege(current_user.id, "WRITE_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_ROLES",
        )

    success = await rbac.remove_privilege_from_role(role_name, request.privilege_name)
    if not success:
        raise HTTPException(status_code=404, detail="Role or privilege not found")

    return {
        "message": f"Privilege '{request.privilege_name}' removed from role '{role_name}'"
    }


# ==================== User Privilege Endpoints ====================


async def _resolve_user(user_uuid: str, db: AsyncSession) -> User:
    """Resolve a user by uuid (ids are never exposed to the API)."""
    result = await db.execute(select(User).filter(User.uuid == user_uuid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/me/privileges", response_model=UserPrivilegesResponse)
async def get_my_privileges(
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Get effective privileges for the current user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    privileges = await rbac.get_user_privileges(current_user.id)

    return UserPrivilegesResponse(
        user_uuid=str(current_user.uuid), privileges=privileges
    )


@router.get("/users/{user_uuid}/privileges", response_model=UserPrivilegesResponse)
async def get_user_privileges(
    user_uuid: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Get effective privileges for a user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    target = await _resolve_user(user_uuid, db)
    if not await rbac.has_privilege(current_user.id, "READ_USER_PRIVILEGES"):
        # Users can only view their own privileges
        if current_user.id != target.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing required privilege: READ_USER_PRIVILEGES",
            )

    privileges = await rbac.get_user_privileges(target.id)

    return UserPrivilegesResponse(user_uuid=user_uuid, privileges=privileges)


@router.get("/users/{user_uuid}/roles", response_model=UserRolesResponse)
async def get_user_roles(
    user_uuid: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Get the roles directly assigned to a user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    target = await _resolve_user(user_uuid, db)
    if not await rbac.has_privilege(current_user.id, "READ_USER_PRIVILEGES"):
        if current_user.id != target.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing required privilege: READ_USER_PRIVILEGES",
            )

    roles = await rbac.get_user_roles(target.id)
    return UserRolesResponse(user_uuid=user_uuid, roles=roles)


@router.get(
    "/users/{user_uuid}/direct-privileges", response_model=UserPrivilegesResponse
)
async def get_user_direct_privileges(
    user_uuid: str,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Get privileges assigned directly to a user (excluding role-inherited)."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    target = await _resolve_user(user_uuid, db)
    if not await rbac.has_privilege(current_user.id, "READ_USER_PRIVILEGES"):
        if current_user.id != target.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing required privilege: READ_USER_PRIVILEGES",
            )

    privileges = await rbac.get_user_direct_privileges(target.id)
    return UserPrivilegesResponse(user_uuid=user_uuid, privileges=privileges)


@router.put("/users/{user_uuid}/roles")
async def assign_role_to_user(
    user_uuid: str,
    request: AssignRoleRequest,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Assign a role to a user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_USER_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_ROLES",
        )

    target = await _resolve_user(user_uuid, db)
    success = await rbac.assign_role_to_user(target.id, request.role_name)
    if not success:
        raise HTTPException(status_code=404, detail="User or role not found")

    return {"message": f"Role '{request.role_name}' assigned to user"}


@router.delete("/users/{user_uuid}/roles")
async def remove_role_from_user(
    user_uuid: str,
    request: AssignRoleRequest,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Remove a role from a user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_USER_ROLES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_ROLES",
        )

    target = await _resolve_user(user_uuid, db)
    success = await rbac.remove_role_from_user(target.id, request.role_name)
    if not success:
        raise HTTPException(status_code=404, detail="User or role not found")

    return {"message": f"Role '{request.role_name}' removed from user"}


@router.put("/users/{user_uuid}/privileges")
async def assign_direct_privilege_to_user(
    user_uuid: str,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Assign a direct privilege to a user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_USER_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_PRIVILEGES",
        )

    target = await _resolve_user(user_uuid, db)
    success = await rbac.assign_direct_privilege_to_user(
        target.id, request.privilege_name
    )
    if not success:
        raise HTTPException(status_code=404, detail="User or privilege not found")

    return {
        "message": f"Direct privilege '{request.privilege_name}' assigned to user"
    }


@router.delete("/users/{user_uuid}/privileges")
async def remove_direct_privilege_from_user(
    user_uuid: str,
    request: AssignPrivilegeRequest,
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Remove a direct privilege from a user."""
    redis_client = await get_redis_client()
    rbac = get_rbac_service(db, redis_client)

    if not await rbac.has_privilege(current_user.id, "WRITE_USER_PRIVILEGES"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing required privilege: WRITE_USER_PRIVILEGES",
        )

    target = await _resolve_user(user_uuid, db)
    success = await rbac.remove_direct_privilege_from_user(
        target.id, request.privilege_name
    )
    if not success:
        raise HTTPException(status_code=404, detail="User or privilege not found")

    return {
        "message": f"Direct privilege '{request.privilege_name}' removed from user"
    }


# ==================== Role Group Endpoints ====================


@router.get("/role-groups", response_model=list)
async def get_role_groups(
    current_user: User = Depends(get_current_user_required()),
    db: AsyncSession = Depends(get_async_db),
):
    """Get all role groups."""
    result = await db.execute(select(RoleGroup))
    role_groups = result.scalars().all()
    return role_groups
