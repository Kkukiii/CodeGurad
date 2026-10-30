import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth import auth_is_configured, current_user
from .limits import enforce_instance_request_limit, enforce_review_quota
from .module_loader import load_modules
from .pipeline import REVIEWS, run_review
from .schemas import ChatRequest, ChatResponse, Review, ReviewRequest
from .storage import count_recent_reviews, create_review, delete_review, fail_job, get_job, get_review as get_stored_review, init_db, list_reviews
from .worker import enqueue_job


app = FastAPI(title="Secure Review", version="0.1.0")
logger = logging.getLogger("secure_review.api")


def allowed_origins() -> list[str]:
    configured = os.getenv("CORS_ALLOWED_ORIGINS")
    return [origin.strip() for origin in configured.split(",") if origin.strip()] if configured else [
        "http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5173", "http://127.0.0.1:5173",
    ]


def ensure_db() -> None:
    try:
        init_db()
    except Exception as error:
        raise HTTPException(status_code=503, detail="Persistence is unavailable") from error


def require_local_compatibility_routes() -> None:
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise HTTPException(status_code=404, detail="Not found")


class RequestControlsMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        incoming_id = headers.get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming_id if re.fullmatch(r"[A-Za-z0-9._-]{1,80}", incoming_id) else str(uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        client = scope.get("client")
        client_host = client[0] if client else "unknown"
        status_code: int | None = None

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_headers = list(message.get("headers", []))
                if not any(name.lower() == b"x-request-id" for name, _ in response_headers):
                    response_headers.append((b"x-request-id", request_id.encode("ascii")))
                message = {**message, "headers": response_headers}
            await send(message)

        def log_completion() -> None:
            if status_code is not None:
                logger.info(
                    "request_complete",
                    extra={
                        "request_id": request_id,
                        "method": scope["method"],
                        "path": scope["path"],
                        "status_code": status_code,
                    },
                )

        try:
            enforce_instance_request_limit(client_host)
        except HTTPException as error:
            response = JSONResponse(status_code=error.status_code, content={"detail": error.detail})
            await response(scope, receive, send_with_request_id)
            log_completion()
            return

        max_body_bytes = int(os.getenv("MAX_REQUEST_BODY_BYTES", "110000"))
        received = 0
        buffered_body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > max_body_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body exceeds the configured limit"},
                )
                await response(scope, receive, send_with_request_id)
                log_completion()
                return
            buffered_body.extend(chunk)
            if not message.get("more_body", False):
                break

        body_sent = False

        async def replay_receive() -> Message:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": bytes(buffered_body), "more_body": False}
            return await receive()

        try:
            await self.app(scope, replay_receive, send_with_request_id)
        finally:
            log_completion()


app.add_middleware(RequestControlsMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_methods=["DELETE", "GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_response(_request: Request, error: RequestValidationError) -> JSONResponse:
    errors = [
        {
            "loc": list(item["loc"]),
            "msg": item["msg"],
            "type": item["type"],
        }
        for item in error.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/live")
def live_health() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready_health() -> dict[str, str]:
    import os

    try:
        ensure_db()
    except Exception as error:
        raise HTTPException(status_code=503, detail="Persistence is unavailable") from error
    if not auth_is_configured():
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    if (
        os.getenv("APP_ENV", "development").lower() == "production"
        and os.getenv("PUBLIC_REVIEWS_ENABLED", "false").lower() == "true"
        and (
            os.getenv("WORKER_MODE", "").lower() != "external"
            or not os.getenv("WORKER_DATABASE_URL")
        )
    ):
        raise HTTPException(status_code=503, detail="Review worker is not configured")
    return {"status": "ready"}


@app.get("/api/modules")
def modules() -> list[dict[str, object]]:
    return [module.model_dump(exclude={"system_prompt"}) for module in load_modules() if module.enabled]


@app.post("/api/review", response_model=Review)
def review(request: ReviewRequest) -> Review:
    require_local_compatibility_routes()
    try:
        return run_review(request.code, request.filename)
    except ValueError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error


@app.get("/api/review/{review_id}", response_model=Review)
def get_review(review_id: str) -> Review:
    require_local_compatibility_routes()
    found = REVIEWS.get(review_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return found


@app.post("/api/v1/reviews", response_model=Review, status_code=status.HTTP_201_CREATED)
def create_secure_review(request: ReviewRequest, user_id: str = Depends(current_user)) -> Review:
    if (
        os.getenv("APP_ENV", "development").lower() == "production"
        and os.getenv("PUBLIC_REVIEWS_ENABLED", "false").lower() != "true"
    ):
        raise HTTPException(status_code=503, detail="Review processing is disabled")
    try:
        ensure_db()
        since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        enforce_review_quota(count_recent_reviews(user_id, since))
        review_id, job_id = create_review(user_id, request.code, request.filename)
        try:
            enqueue_job(job_id)
        except Exception as error:
            fail_job(job_id, f"Worker dispatch failed ({type(error).__name__})")
            logger.error(
                "worker_dispatch_failed",
                extra={"job_id": job_id, "error_type": type(error).__name__},
            )
            raise HTTPException(status_code=503, detail="Worker is unavailable") from None
        stored = get_stored_review(user_id, review_id)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if stored is None:
        raise HTTPException(status_code=500, detail="Review could not be stored")
    return stored


@app.get("/api/v1/reviews", response_model=list[Review])
def list_secure_reviews(user_id: str = Depends(current_user)) -> list[Review]:
    ensure_db()
    return list_reviews(user_id)


@app.get("/api/v1/reviews/{review_id}", response_model=Review)
def get_secure_review(review_id: str, user_id: str = Depends(current_user)) -> Review:
    ensure_db()
    found = get_stored_review(user_id, review_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return found


@app.delete("/api/v1/reviews/{review_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secure_review(review_id: str, user_id: str = Depends(current_user)) -> Response:
    ensure_db()
    if not delete_review(user_id, review_id):
        raise HTTPException(status_code=404, detail="Review not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/v1/reviews/{review_id}/findings")
def secure_review_findings(review_id: str, user_id: str = Depends(current_user)) -> list[dict[str, object]]:
    review = get_secure_review(review_id, user_id)
    return [finding.model_dump() for finding in review.findings]


@app.get("/api/v1/jobs/{job_id}")
def secure_job(job_id: str, user_id: str = Depends(current_user)) -> dict[str, object]:
    ensure_db()
    job = get_job(user_id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job["id"],
        "review_id": job["review_id"],
        "status": job["status"],
        "attempts": job["attempts"],
        "error": "Analysis failed before completion" if job["status"] == "failed" else None,
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
    }


@app.post("/api/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    require_local_compatibility_routes()
    review = REVIEWS.get(request.review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    message = request.message.lower()
    if "why" in message or "fix" in message or "remediat" in message:
        answer = "This local assistant can explain findings returned by the evidence-backed review. " + " ".join(
            f"{finding.title}: {finding.description}" for finding in review.findings[:3]
        )
    else:
        answer = "Ask about one of the flagged findings, its evidence, or its remediation guidance."
    return ChatResponse(answer=answer, sources=[reference for finding in review.findings for reference in (finding.fix.references if finding.fix else [])])


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent.parent / "static" / "index.html")
