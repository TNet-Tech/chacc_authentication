"""
RBAC (Role-Based Access Control) Service with Graceful Redis Degradation.

This service provides:
- Privilege management (read, create, update, delete)
- Role management (create, assign privileges, assign to users)
- User privilege calculation (role privileges + direct privileges)
- Redis caching for high-performance privilege lookups
- Automatic cache invalidation on changes

The service follows the Hybrid DB/Redis pattern:
- Redis is used for high-speed privilege caching
- PostgreSQL is the ultimate source of truth
- If Redis is unavailable, the system seamlessly falls back to PostgreSQL
"""

import json
import logging
from typing import Optional, List

from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from chacc_authentication.module.models.rbac import Privilege, Role
from chacc_authentication.module.models.user import User

logger = logging.getLogger(__name__)

# Cache TTL for user privileges (1 hour)
PRIVILEGE_CACHE_TTL = 3600


class RBACService:
    """
    RBAC Service with Hybrid DB/Redis Fallback.

    Redis is used as a fast cache layer for user privileges,
    but the DB always has the final say.
    """

    def __init__(self, db: AsyncSession, redis_client=None):
        self.db = db
        self.redis = redis_client

    def _get_redis_client(self):
        """Get Redis client if available."""
        return self.redis

    async def get_privileges_by_names(self, names: List[str]) -> List[Privilege]:
        """Get multiple privileges by name in a single query."""
        if not names:
            return []
        result = await self.db.execute(
            select(Privilege).filter(Privilege.name.in_(names))
        )
        return result.scalars().all()

    async def get_privilege_by_name(self, name: str) -> Optional[Privilege]:
        """Get a privilege by name."""
        result = await self.db.execute(
            select(Privilege).filter(Privilege.name == name)
        )
        return result.scalar_one_or_none()

    async def get_all_privileges(self) -> List[Privilege]:
        """Get all privileges."""
        result = await self.db.execute(select(Privilege))
        return result.scalars().all()

    async def get_privilege_names(self) -> List[str]:
        """Get the names of all privileges."""
        result = await self.db.execute(select(Privilege.name))
        return [row[0] for row in result.all()]

    async def create_privilege(
        self, name: str, description: str, severity: str
    ) -> Privilege:
        """Create a new privilege."""
        privilege = Privilege(name=name, description=description, severity=severity)
        self.db.add(privilege)
        await self.db.commit()
        await self.db.refresh(privilege)
        logger.info(f"Created privilege: {name}")
        return privilege

    async def update_privilege(
        self,
        name: str,
        description: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Optional[Privilege]:
        """Update an existing privilege's description and/or severity."""
        privilege = await self.get_privilege_by_name(name)
        if privilege is None:
            return None
        if description is not None:
            privilege.description = description
        if severity is not None:
            privilege.severity = severity
        await self.db.commit()
        await self.db.refresh(privilege)
        logger.info(f"Updated privilege: {name}")
        return privilege

    async def delete_privilege(self, name: str) -> bool:
        """Delete a privilege by name. Returns False if it does not exist."""
        privilege = await self.get_privilege_by_name(name)
        if privilege is None:
            return False
        await self.db.delete(privilege)
        await self.db.commit()
        # Effective privileges may have changed for many users.
        await self._invalidate_all_user_cache()
        logger.info(f"Deleted privilege: {name}")
        return True


    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get a role by name."""
        result = await self.db.execute(
            select(Role)
            .options(selectinload(Role.privileges))
            .filter(Role.name == name)
        )
        return result.scalar_one_or_none()

    async def get_all_roles(self) -> List[Role]:
        """Get all roles."""
        result = await self.db.execute(
            select(Role).options(selectinload(Role.privileges))
        )
        return result.scalars().all()

    async def get_role_names(self) -> List[str]:
        """Get the names of all roles."""
        result = await self.db.execute(select(Role.name))
        return [row[0] for row in result.all()]

    async def create_role(
        self,
        name: str,
        description: str,
        is_system: bool = False,
        privilege_names: Optional[List[str]] = None,
    ) -> Role:
        """Create a new role, optionally attaching an initial set of privileges."""
        resolved = []
        for priv_name in privilege_names or []:
            privilege = await self.get_privilege_by_name(priv_name)
            if privilege is None:
                raise ValueError(f"Privilege '{priv_name}' does not exist")
            resolved.append(privilege)

        role = Role(
            name=name, description=description, is_system=is_system, privileges=resolved
        )
        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role, attribute_names=["id", "uuid", "created_at"])
        logger.info(f"Created role: {name}")
        return role

    async def update_role(
        self,
        name: str,
        description: Optional[str] = None,
        new_name: Optional[str] = None,
        privilege_names: Optional[List[str]] = None,
    ) -> Optional[Role]:
        """Update a role's name, description and/or assigned privileges.

        Unlike privileges, role names are safe to change (users link to roles by
        id), but system roles are re-seeded by name on startup, so renaming them
        is disallowed to avoid duplicates.
        """
        role = await self.get_role_by_name(name)
        if role is None:
            return None

        if new_name is not None and new_name != role.name:
            if getattr(role, "is_system", False):
                raise ValueError("System roles cannot be renamed")
            existing = await self.get_role_by_name(new_name)
            if existing and existing.id != role.id:
                raise ValueError(f"Role '{new_name}' already exists")
            role.name = new_name

        if description is not None:
            role.description = description

        if privilege_names is not None:
            resolved = []
            for priv_name in privilege_names:
                privilege = await self.get_privilege_by_name(priv_name)
                if privilege is None:
                    raise ValueError(f"Privilege '{priv_name}' does not exist")
                resolved.append(privilege)
            role.privileges = resolved

        await self.db.commit()
        await self.db.refresh(role)
        await self._invalidate_all_user_cache()
        logger.info(f"Updated role: {name}")
        return role

    async def delete_role(self, name: str) -> bool:
        """Delete a non-system role by name. Returns False if it does not exist."""
        role = await self.get_role_by_name(name)
        if role is None:
            return False
        if getattr(role, "is_system", False):
            raise ValueError("System roles cannot be deleted")
        await self.db.delete(role)
        await self.db.commit()
        await self._invalidate_all_user_cache()
        logger.info(f"Deleted role: {name}")
        return True

    async def assign_privilege_to_role(
        self, role_name: str, privilege_name: str
    ) -> bool:
        """Assign a privilege to a role."""
        role = await self.get_role_by_name(role_name)
        privilege = await self.get_privilege_by_name(privilege_name)

        if not role or not privilege:
            return False

        if privilege not in role.privileges:
            role.privileges.append(privilege)
            await self.db.commit()
            logger.info(f"Assigned privilege {privilege_name} to role {role_name}")

        await self._invalidate_all_user_cache()

        return True

    async def remove_privilege_from_role(
        self, role_name: str, privilege_name: str
    ) -> bool:
        """Remove a privilege from a role."""
        role = await self.get_role_by_name(role_name)
        privilege = await self.get_privilege_by_name(privilege_name)

        if not role or not privilege:
            return False

        if privilege in role.privileges:
            role.privileges.remove(privilege)
            await self.db.commit()
            logger.info(f"Removed privilege {privilege_name} from role {role_name}")

        await self._invalidate_all_user_cache()

        return True

    
    async def get_user_privileges(self, user_id: int) -> List[str]:
        """
        Get effective privileges for a user.

        This includes:
        - Direct privileges assigned to the user
        - Privileges from roles assigned to the user
        - ALL privilege grants all access

        Uses Redis cache with graceful degradation to PostgreSQL.
        """
        cache_key = f"user_privileges:{user_id}"

        redis_client = self._get_redis_client()
        if redis_client:
            try:
                cached = await redis_client.get(cache_key)
                if cached:
                    logger.debug(f"Cache hit for user {user_id} privileges")
                    return json.loads(cached)
            except Exception as e:
                logger.warning(f"Redis unavailable, falling back to DB for RBAC: {e}")

        privileges = await self._calculate_effective_privileges_from_db(user_id)
        priv_names = [p.name for p in privileges]

        if redis_client:
            try:
                await redis_client.setex(
                    cache_key, PRIVILEGE_CACHE_TTL, json.dumps(priv_names)
                )
            except Exception as e:
                logger.warning(f"Failed to cache privileges for user {user_id}: {e}")

        return priv_names

    async def get_user_roles(self, user_id: int) -> List[str]:
        """Get the names of roles directly assigned to a user."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.roles))
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            return []
        return [role.name for role in user.roles]

    async def get_user_direct_privileges(self, user_id: int) -> List[str]:
        """Get the names of privileges assigned directly to a user (not via roles)."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.direct_privileges))
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            return []
        return [privilege.name for privilege in user.direct_privileges]

    async def _calculate_effective_privileges_from_db(
        self, user_id: int
    ) -> List[Privilege]:
        """
        Calculate effective privileges from database.

        This includes:
        - Direct privileges assigned to the user
        - Privileges from all roles assigned to the user
        """
        result = await self.db.execute(
            select(User)
            .options(
                selectinload(User.roles).selectinload(Role.privileges),
                selectinload(User.direct_privileges),
            )
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            return []

        role_privilege_ids = set()
        for role in user.roles:
            for privilege in role.privileges:
                role_privilege_ids.add(privilege.id)

        direct_privilege_ids = {p.id for p in user.direct_privileges}

        all_privilege_ids = role_privilege_ids.union(direct_privilege_ids)

        if all_privilege_ids:
            result = await self.db.execute(
                select(Privilege).filter(Privilege.id.in_(all_privilege_ids))
            )
            privileges = result.scalars().all()
        else:
            privileges = []

        return privileges

    async def assign_role_to_user(self, user_id: int, role_name: str) -> bool:
        """Assign a role to a user."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.roles))
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        role = await self.get_role_by_name(role_name)

        if not user or not role:
            return False

        if role not in user.roles:
            user.roles.append(role)
            await self.db.commit()
            logger.info(f"Assigned role {role_name} to user {user_id}")

        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)

        return True

    async def remove_role_from_user(self, user_id: int, role_name: str) -> bool:
        """Remove a role from a user."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.roles))
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        role = await self.get_role_by_name(role_name)

        if not user or not role:
            return False

        if role in user.roles:
            user.roles.remove(role)
            await self.db.commit()
            logger.info(f"Removed role {role_name} from user {user_id}")

        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)

        return True

    async def assign_direct_privilege_to_user(
        self, user_id: int, privilege_name: str
    ) -> bool:
        """Assign a direct privilege to a user."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.direct_privileges))
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        privilege = await self.get_privilege_by_name(privilege_name)

        if not user or not privilege:
            return False

        if privilege not in user.direct_privileges:
            user.direct_privileges.append(privilege)
            await self.db.commit()
            logger.info(f"Assigned direct privilege {privilege_name} to user {user_id}")

        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)

        return True

    async def remove_direct_privilege_from_user(
        self, user_id: int, privilege_name: str
    ) -> bool:
        """Remove a direct privilege from a user."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.direct_privileges))
            .filter(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        privilege = await self.get_privilege_by_name(privilege_name)

        if not user or not privilege:
            return False

        if privilege in user.direct_privileges:
            user.direct_privileges.remove(privilege)
            await self.db.commit()
            logger.info(
                f"Removed direct privilege {privilege_name} from user {user_id}"
            )

        # Invalidate user's privilege cache
        await self.invalidate_user_cache(user_id)

        return True

    async def invalidate_user_cache(self, user_id: int):
        """Invalidate a user's privilege cache."""
        cache_key = f"user_privileges:{user_id}"
        redis_client = self._get_redis_client()

        if redis_client:
            try:
                await redis_client.delete(cache_key)
                logger.debug(f"Invalidated cache for user {user_id}")
            except Exception as e:
                logger.warning(f"Failed to invalidate cache for user {user_id}: {e}")

    async def _invalidate_all_user_cache(self):
        """Invalidate all user privilege caches (use with caution)."""
        # This is expensive - in production, consider using cache tags or patterns
        redis_client = self._get_redis_client()

        if redis_client:
            try:
                # Get all keys matching user_privileges:*
                keys_to_delete = []
                async for key in redis_client.scan_iter(match="user_privileges:*"):
                    keys_to_delete.append(key)

                if keys_to_delete:
                    await redis_client.delete(*keys_to_delete)
                    logger.info(
                        f"Invalidated {len(keys_to_delete)} user privilege caches"
                    )
            except Exception as e:
                logger.warning(f"Failed to invalidate all user caches: {e}")

    # ==================== Privilege Check ====================

    async def has_privilege(self, user_id: int, privilege_name: str) -> bool:
        """
        Check if a user has a specific privilege.

        Users with ALL privilege automatically have all privileges.
        """
        user_privs = await self.get_user_privileges(user_id)

        # Check for ALL privilege (super user)
        if "ALL" in user_privs:
            return True

        return privilege_name in user_privs

    async def has_any_privilege(self, user_id: int, privilege_names: List[str]) -> bool:
        """Check if a user has any of the specified privileges."""
        user_privs = await self.get_user_privileges(user_id)

        # Check for ALL privilege (super user)
        if "ALL" in user_privs:
            return True

        return any(p in user_privs for p in privilege_names)


def get_rbac_service(db: AsyncSession, redis_client=None) -> RBACService:
    """Create an RBACService instance."""
    return RBACService(db, redis_client)
