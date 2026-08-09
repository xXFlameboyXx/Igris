"""API v1 router composition."""

from fastapi import APIRouter

from igris.api.v1.health import router as health_router

router = APIRouter()
router.include_router(health_router, tags=["health"])

