from chacc_authentication.module.services import (
    create_default_user,
    ensure_default_admin_privileges,
)
from chacc_api import BackboneContext
from typing import Optional
from chacc_authentication.module.auth import get_current_user, get_password_hash
from chacc_authentication.module.routes import router as auth_router, registerRouter
from chacc_authentication.module.routes_rbac import router as rbac_router
from chacc_authentication.module.context_factory import get_context, set_module_context
from chacc_authentication.module.models import DEFAULT_PRIVILEGES, DEFAULT_ROLES, User
from chacc_authentication.module.services.rbac_service import get_rbac_service
from chacc_authentication.module.services.privilege_provider import (
    PrivilegeService,
    has_privileges,
)


async def initialize_rbac_defaults(module_context: BackboneContext):
    """
    Initialize default privileges and roles for RBAC.

    This function ensures that the default system privileges and roles
    are created on first startup if they don't exist.
    """
    try:

        db_gen = module_context.get_db_async()
        db = await db_gen.__anext__()

        redis_service = module_context.get_service("redis")
        redis_client = None
        if redis_service:
            try:
                redis_client = await redis_service.get_client()
            except Exception:
                pass

        rbac = get_rbac_service(db, redis_client)

        existing_priv_names = set(await rbac.get_privilege_names())
        existing_role_names = set(await rbac.get_role_names())
        
        for priv_data in DEFAULT_PRIVILEGES:
            if priv_data["name"] not in existing_priv_names:
                try:
                    await rbac.create_privilege(**priv_data)
                    module_context.logger.info(f"Created privilege: {priv_data['name']}")
                except Exception as e:
                    module_context.logger.warning(f"Could not create privilege {priv_data['name']}: {e}")
        
        for role_data in DEFAULT_ROLES:
            if role_data["name"] not in existing_role_names:
                try:
                    await rbac.create_role(**role_data)
                    module_context.logger.info(f"Created role: {role_data['name']}")
                except Exception as e:
                    module_context.logger.warning(f"Could not create role {role_data['name']}: {e}")

        module_context.logger.info("RBAC defaults initialization completed")
    except Exception as e:
        module_context.logger.warning(f"RBAC defaults initialization skipped: {e}")
    finally:
        try:
            await db_gen.aclose()
        except Exception:
            pass


async def setup_plugin(context: Optional[BackboneContext] = None):
    """
    This function is called by the ChaCC API backbone to initialize your module.
    It can also be called in development mode without a context.
    """
    _module_context = get_context(context)
    set_module_context(_module_context)

    _module_context.logger.info("authentication: Setup initiated!")

    _module_context.register_service("get_current_user", get_current_user)
    _module_context.register_service("UserModel", User)
    _module_context.register_service("get_password_hash", get_password_hash)

    _module_context.register_service(
        "privilege_service", PrivilegeService(_module_context)
    )
    _module_context.register_service("has_privileges", has_privileges)

    await initialize_rbac_defaults(_module_context)

    await create_default_user(_module_context)

    await ensure_default_admin_privileges(_module_context)

    if (
        _module_context.get_module_config(
            "ENABLE_SELF_REGISTRATION", "authentication", default="false"
        ).lower()
        == "true"
    ):
        _module_context.logger.info(
            "ChaCC-Authentication: Self-registration is enabled."
        )
        auth_router.include_router(registerRouter)

    auth_router.include_router(rbac_router)
    return auth_router


def get_plugin_info():
    """
    Provides essential information about this module to the ChaCC API backbone.
    """
    return {
        "name": "authentication",
        "display_name": "Authentication Module",
        "version": "0.1.0",
        "author": "Your Name/Organization",
        "description": "A new ChaCC API module for authentication functionality.",
        "status": "enabled",
    }
