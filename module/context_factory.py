"""
Context factory for providing BackboneContext in different environments.
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import HTTPException
from chacc_api import BackboneContext

_module_context: Optional[BackboneContext] = None


def set_module_context(context: BackboneContext):
    """Set the module context (called by main.py)."""
    global _module_context
    _module_context = context


def get_module_context() -> Optional[BackboneContext]:
    """Get the module context (used by auth.py to avoid circular imports)."""
    return _module_context


class ContextFactory:
    """Factory for creating appropriate BackboneContext based on environment."""

    @staticmethod
    def get_context(context: Optional[BackboneContext] = None) -> BackboneContext:
        """
        Get backbone context from ChaCC API.

        Args:
            context: Provided context (when running in backbone)

        Returns:
            BackboneContext instance
        """
        if context is not None:
            return context

        raise RuntimeError(
            "No context provided. This module requires the ChaCC backbone to run."
        )

    @staticmethod
    def is_backbone_available() -> bool:
        """Check if we're running within the ChaCC backbone."""
        return os.getenv("CHACC_BACKBONE") == "true"

    @staticmethod
    def require_backbone():
        """Raise error if not running in backbone (for production modules)."""
        if not ContextFactory.is_backbone_available():
            raise RuntimeError(
                "This module requires the ChaCC backbone to be available. "
                "Use development context for testing: CHACC_ENV=development"
            )


def get_context(context: Optional[BackboneContext] = None) -> BackboneContext:
    """Get context using the factory."""
    return ContextFactory.get_context(context)


async def get_db():
    """Route dependency: a sync database session, closed after the request.

    Kept as a generator so the backbone's session generator is closed here, in
    the request's own task. Returning ``await anext(...)`` instead dropped the
    generator, and Python then closed it later from another task, possibly while
    the route was still using the session.
    """
    context: BackboneContext = get_module_context()
    if context is None:
        raise HTTPException(status_code=500, detail="Module not initialized")

    gen = context.get_db()
    db = await anext(gen)
    try:
        yield db
    finally:
        await gen.aclose()


@asynccontextmanager
async def async_session(context: Optional[BackboneContext] = None):
    """An async database session for code outside routes, closed when the block ends.

        async with async_session() as db:
            user = (await db.execute(select(User))).scalar_one_or_none()

    Don't take a session with ``await anext(context.get_db_async())``: the
    generator is dropped, and Python closes it later from another task. That
    closes the session while it is still in use ("CLOSE FAILED: ... is already
    in progress") and leaves its connection checked out, until the pool runs
    dry. Here the generator is closed in the same task. Closing the session
    rolls back anything not committed.
    """
    context = context or get_module_context()
    if context is None:
        raise RuntimeError("The authentication module is not initialized.")

    gen = context.get_db_async()
    db = await anext(gen)
    try:
        yield db
    finally:
        await gen.aclose()


async def get_async_db():
    """Get async database session from module context.

    Delegates to the backbone's get_async_db which handles session lifecycle
    (creation, rollback on exception, cleanup).
    """
    context = get_module_context()
    if context is None:
        raise HTTPException(status_code=500, detail="Module not initialized")
    
    gen = context.get_db_async()
    db = await anext(gen)
    try:
        yield db
    finally:
        await gen.aclose()


async def get_redis_client():
    """Get Redis client from module context."""
    context = get_module_context()
    if context is None:
        return None

    redis_service = context.get_service("redis")
    if redis_service is None:
        return None

    try:
        return await redis_service.get_client()
    except Exception:
        return None