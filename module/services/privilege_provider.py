"""
Cross-module privilege provider.

This module exposes two services through the ChaCC backbone so that *other*
plugins can manage and enforce privileges WITHOUT importing anything from the
authentication package:

- ``privilege_service`` — a self-contained facade for create/update/delete/read
  of privileges. Other modules retrieve it with
  ``context.get_service("privilege_service")`` and call its async methods.

- ``has_privileges`` — an authorization helper meant to back a FastAPI
  dependency, mirroring how ``get_current_user`` is exposed. Other modules
  retrieve it with ``context.get_service("has_privileges")`` and call it from
  their own dependency wrapper (see the menu module for an example).

Both helpers manage their own database session via the authentication module
context, so callers never need direct DB or model access.
"""

from typing import List, Optional

from fastapi import HTTPException, status

from chacc_authentication.module.context_factory import get_module_context
from chacc_authentication.module.services.rbac_service import get_rbac_service


async def _get_redis_client(context) -> Optional[object]:
    """Resolve the shared redis client if the backbone provides one."""
    redis_service = context.get_service("redis") if context else None
    if not redis_service:
        return None
    try:
        return await redis_service.get_client()
    except Exception:
        return None


async def _new_rbac(context):
    """Build an RBACService bound to a fresh DB session + redis (if available)."""
    db = await anext(context.get_db_async())
    redis_client = await _get_redis_client(context)
    return get_rbac_service(db, redis_client)


class PrivilegeService:
    """Self-contained privilege management for use by any plugin.

    Example (from another module, no auth import required)::

        svc = context.get_service("privilege_service")
        await svc.ensure("MENU_MANAGE", "Manage menus", "HIGH")
    """

    def __init__(self, context):
        self._context = context

    def _ctx(self):
        return self._context or get_module_context()

    async def list(self) -> List[dict]:
        rbac = await _new_rbac(self._ctx())
        return [_to_dict(p) for p in await rbac.get_all_privileges()]

    async def get(self, name: str) -> Optional[dict]:
        rbac = await _new_rbac(self._ctx())
        privilege = await rbac.get_privilege_by_name(name)
        return _to_dict(privilege) if privilege else None

    async def create(
        self, name: str, description: str, severity: str = "MEDIUM"
    ) -> dict:
        rbac = await _new_rbac(self._ctx())
        existing = await rbac.get_privilege_by_name(name)
        if existing:
            raise ValueError(f"Privilege '{name}' already exists")
        return _to_dict(await rbac.create_privilege(name, description, severity))

    async def ensure(
        self, privileges: List[tuple[str, str, str]]
    ) -> List[dict]:
        """Idempotent bulk create — safe to call on every startup.

        Args:
            privileges: List of (name, description, severity) tuples.

        Returns:
            List of privilege dicts for all requested privileges.
        """
        names = [name for name, _, _ in privileges]
        rbac = await _new_rbac(self._ctx())
        existing = await rbac.get_privileges_by_names(names)
        existing_by_name = {p.name: p for p in existing}

        results = []
        for name, description, severity in privileges:
            if name in existing_by_name:
                results.append(_to_dict(existing_by_name[name]))
            else:
                created = await rbac.create_privilege(name, description, severity)
                results.append(_to_dict(created))
        return results

    async def update(
        self,
        name: str,
        description: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Optional[dict]:
        rbac = await _new_rbac(self._ctx())
        updated = await rbac.update_privilege(name, description, severity)
        return _to_dict(updated) if updated else None

    async def delete(self, name: str) -> bool:
        rbac = await _new_rbac(self._ctx())
        return await rbac.delete_privilege(name)


def _to_dict(privilege) -> dict:
    return {
        "id": privilege.id,
        "uuid": str(privilege.uuid),
        "name": privilege.name,
        "description": privilege.description,
        "severity": privilege.severity,
    }


async def has_privileges(
    credentials,
    privilege_names: List[str],
    *,
    require_all: bool = False,
):
    """Authorization check backing a cross-module FastAPI dependency.

    Resolves the current user from bearer ``credentials`` (the same object
    ``get_current_user`` accepts), verifies the user holds the required
    privilege(s), and returns the user. Raises 401 if unauthenticated and 403
    if the privilege requirement is not met. Users with the ``ALL`` super
    privilege always pass.

    ``require_all=False`` (default) → user needs ANY of ``privilege_names``.
    ``require_all=True`` → user needs EVERY privilege in ``privilege_names``.
    """
    # Imported lazily to avoid a circular import at module load time.
    from chacc_authentication.module.auth import get_current_user

    user = await get_current_user(credentials)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not privilege_names:
        return user

    rbac = await _new_rbac(get_module_context())
    if require_all:
        granted = True
        for name in privilege_names:
            if not await rbac.has_privilege(user.id, name):
                granted = False
                break
    else:
        granted = await rbac.has_any_privilege(user.id, privilege_names)

    if not granted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required privilege(s): {', '.join(privilege_names)}",
        )
    return user
