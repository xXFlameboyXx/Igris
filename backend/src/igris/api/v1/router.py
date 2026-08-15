"""API v1 router composition."""

from fastapi import APIRouter

from igris.api.v1.analyses import router as analyses_router
from igris.api.v1.experiments import router as experiments_router
from igris.api.v1.health import router as health_router
from igris.api.v1.ml import router as ml_router
from igris.api.v1.robustness import router as robustness_router
from igris.api.v1.samples import router as samples_router

router = APIRouter()
router.include_router(health_router, tags=["health"])
router.include_router(samples_router, prefix="/samples", tags=["samples"])
router.include_router(ml_router, prefix="/ml", tags=["ml"])
router.include_router(analyses_router, tags=["analyses"])
router.include_router(experiments_router, tags=["experiments"])
router.include_router(robustness_router, prefix="/robustness", tags=["robustness"])
