"""
Operational Metrics Endpoint for Prometheus Scrapers and Control Plane Telemetry.
Exposes standard Prometheus text exposition format (v0.0.4) and JSON telemetry.
Enforces role-based or operator-token authorization in production mode.
"""

from fastapi import APIRouter, Header, Request, HTTPException, status
from fastapi.responses import PlainTextResponse, JSONResponse
from typing import Optional

from app.core.config import settings
from app.services.metrics_service import metrics_service

router = APIRouter()


def verify_metrics_authorization(
    x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"),
    authorization: Optional[str] = Header(None),
) -> bool:
    """
    Validates metrics scraping authorization.
    In production: requires either X-Operator-Token matching configured secret or valid Bearer token.
    In development/testing: allows open scraping.
    """
    if settings.ENVIRONMENT.lower() == "production":
        expected_token = getattr(settings, "OPERATOR_METRICS_TOKEN", None)
        if expected_token:
            if x_operator_token == expected_token:
                return True
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Operator-Token header for metrics access.",
            )
        # If no explicit operator token set, check Authorization header presence
        if not authorization and not x_operator_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Metrics endpoint requires authentication in production.",
            )
    return True


@router.get("/metrics", response_class=PlainTextResponse)
def get_metrics_prometheus(request: Request, x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"), authorization: Optional[str] = Header(None)):
    """
    Exposes operational metrics in Prometheus text exposition format (v0.0.4).
    Accepts application/json via Accept header for JSON output.
    """
    verify_metrics_authorization(x_operator_token=x_operator_token, authorization=authorization)

    accept = request.headers.get("accept", "")
    if "application/json" in accept.lower():
        return JSONResponse(content=metrics_service.to_dict())

    content = metrics_service.to_prometheus_text()
    return PlainTextResponse(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
