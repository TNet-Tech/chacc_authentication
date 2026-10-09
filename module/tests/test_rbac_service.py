"""
Unit tests for RBACService (module/services/rbac_service.py).
"""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from chacc_authentication.module.models.rbac import Privilege, Role
from chacc_authentication.module.services.rbac_service import RBACService


@pytest_asyncio.fixture
async def async_db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Privilege.metadata.create_all)
    AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def rbac_service(async_db_session):
    return RBACService(db=async_db_session)


class TestGetPrivilegeNames:
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_privileges(self, rbac_service):
        names = await rbac_service.get_privilege_names()
        assert names == []

    @pytest.mark.asyncio
    async def test_returns_names_of_existing_privileges(self, rbac_service, async_db_session):
        async_db_session.add_all([
            Privilege(name="MENU_MANAGE", description="Manage menus", severity="HIGH"),
            Privilege(name="MENU_VIEW_ANALYTICS", description="View analytics", severity="MEDIUM"),
        ])
        await async_db_session.commit()

        names = await rbac_service.get_privilege_names()
        assert set(names) == {"MENU_MANAGE", "MENU_VIEW_ANALYTICS"}


class TestGetRoleNames:
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_roles(self, rbac_service):
        names = await rbac_service.get_role_names()
        assert names == []

    @pytest.mark.asyncio
    async def test_returns_names_of_existing_roles(self, rbac_service, async_db_session):
        async_db_session.add_all([
            Role(name="admin", description="Administrator", is_system=True),
            Role(name="staff", description="Staff member", is_system=False),
        ])
        await async_db_session.commit()

        names = await rbac_service.get_role_names()
        assert set(names) == {"admin", "staff"}


class TestCreateRoleWithPrivileges:
    @pytest.mark.asyncio
    async def test_create_role_without_privilege_names_still_works(self, rbac_service):
        """Baseline: existing callers that don't pass privilege_names are unaffected."""
        role = await rbac_service.create_role(name="EMPTY", description="No privileges")
        assert role.name == "EMPTY"
        assert role.privileges == []

    @pytest.mark.asyncio
    async def test_create_role_with_privilege_names_attaches_them(
        self, rbac_service, async_db_session
    ):
        async_db_session.add_all([
            Privilege(name="ALL", description="Everything", severity="CRITICAL"),
            Privilege(name="MANAGE_SYSTEM", description="Admin access", severity="CRITICAL"),
        ])
        await async_db_session.commit()

        role = await rbac_service.create_role(
            name="ADMIN",
            description="Full system administrator with all privileges",
            privilege_names=["ALL", "MANAGE_SYSTEM"],
        )

        assert {p.name for p in role.privileges} == {"ALL", "MANAGE_SYSTEM"}

    @pytest.mark.asyncio
    async def test_create_role_with_unknown_privilege_name_raises(self, rbac_service):
        with pytest.raises(ValueError, match="NOPE"):
            await rbac_service.create_role(
                name="BROKEN", description="x", privilege_names=["NOPE"]
            )
