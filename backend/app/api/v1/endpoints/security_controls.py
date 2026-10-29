"""
VAPT Platform — Security Control Verification & Mutation Testing API (Prompt 27).
Provides endpoints for inspecting security control mappings, mutation scenarios,
and executing automated mutation drills.
"""
from typing import List
from fastapi import APIRouter, Depends, status

from app.api.deps import require_system_roles
from app.models.user import User, SystemRole
from app.services.security_control_verification_service import security_control_verification_service
from app.schemas.verification_assurance import (
    SecurityControlsCatalogResponse,
    MutationScenario,
    MutationDrillResult,
)

router = APIRouter()


@router.get("/controls", response_model=SecurityControlsCatalogResponse)
def get_security_controls_catalog(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
            SystemRole.SECURITY_TESTER,
        ])
    ),
):
    """
    Returns canonical catalog of security controls, enforcement points, positive and negative tests.
    """
    return security_control_verification_service.get_security_controls_catalog()


@router.get("/mutations", response_model=List[MutationScenario])
def get_mutation_scenarios(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
            SystemRole.SECURITY_TESTER,
        ])
    ),
):
    """
    Returns the catalog of defined mutation testing scenarios and their killer tests.
    """
    return security_control_verification_service.get_mutation_scenarios()


@router.post("/run-mutation-drill", response_model=MutationDrillResult)
def run_mutation_drill(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """
    Executes an on-demand mutation testing drill verifying zero surviving security mutations.
    """
    return security_control_verification_service.run_mutation_drill()
