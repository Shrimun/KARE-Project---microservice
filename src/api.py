""" FastAPI application exposing the question-answering microservice. """

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from functools import lru_cache
from typing import AsyncIterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status, Header
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception, RetryError

from src.config import Settings, get_settings
from src.openai_client import OpenAIClient, OpenAIClientConfig
from src.vector_store import get_vector_store, RetrievedChunk, VectorStore
from src.database import connect_to_mongodb, close_mongodb_connection, get_database
from src.user_service import UserService
from src.models import UserCreate, UserLogin, TokenResponse, UserResponse, LogoutResponse
from src.auth import decode_access_token

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(title="Question Answering Service", version="1.0.0")

# Security
security = HTTPBearer()

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize database connection on startup."""
    logger.info("Starting up application...")
    await connect_to_mongodb()
    logger.info("Application startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection on shutdown."""
    logger.info("Shutting down application...")
    await close_mongodb_connection()
    logger.info("Application shutdown complete")

# Models / validation
class SourceAttribution(BaseModel):
    chunk_id: str
    document: str
    score: float

class AskRequest(BaseModel):
    """Request payload for /ask (question must be non-empty and reasonably sized)."""
    question: str = Field(..., min_length=3, max_length=500, description="Natural language question to answer")

    @validator("question", pre=True)
    def strip_and_validate(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("question must be a string")
        q = v.strip()
        if not q:
            raise ValueError("question must not be empty or whitespace")
        if len(q) < 3:
            raise ValueError("question too short after trimming")
        return q

class AskResponse(BaseModel):
    answer: str
    sources: list[SourceAttribution]

# Cached dependency factories
@lru_cache(maxsize=1)
def _get_vector_store_cached(settings: Settings) -> VectorStore:
    return get_vector_store(settings)

@lru_cache(maxsize=1)
def _get_openai_client_cached(settings: Settings) -> OpenAIClient:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")
    config = OpenAIClientConfig(
        api_key=settings.openai_api_key,
        embed_model=settings.embed_model,
        timeout=settings.openai_timeout,
        max_retries=settings.max_embed_retries,
    )
    return OpenAIClient(config)

# Retry/backoff configuration
_MAX_RETRIES = 5
_WAIT = wait_exponential(multiplier=1, min=1, max=30)  # exponential backoff with cap

def _should_retry(exc: Exception) -> bool:
    """Return True if exception appears transient (429 or 5xx-like or network timeouts)."""
    # If the exception has an HTTP-like status attribute
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    try:
        if status is not None:
            code = int(status)
            if code == 429 or 500 <= code < 600:
                return True
    except Exception:
        # ignore conversion errors and fall back to message-based checks
        pass

    msg = str(exc).lower()
    if "rate limit" in msg or "too many requests" in msg or "429" in msg:
        return True
    if "server error" in msg or "internal" in msg or "temporar" in msg:
        return True

    # Common transient network errors - treat as retryable
    if isinstance(exc, TimeoutError):
        return True

    return False

# ---------------------------
# Exception handlers (centralized & sanitized responses)
# ---------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Keep the detailed list shape (422) — useful for client debugging, but can be shortened
    logger.info("Validation error for %s %s: %s", request.method, request.url, exc.errors())
    return _error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        message="Validation failed",
        details=exc.errors(),
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Normalize detail shape while preserving status code.
    detail = exc.detail
    if isinstance(detail, str) and detail.strip():
        message = detail.strip()
        details = None
    else:
        message = "Request failed"
        details = detail
    logger.info(
        "HTTP exception %s for %s %s: %s",
        exc.status_code,
        request.method,
        request.url,
        {"message": message, "details": details},
    )
    return _error_response(status_code=exc.status_code, message=message, details=details)

@app.exception_handler(RetryError)
async def retry_exception_handler(request: Request, exc: RetryError):
    # Tenacity exhausted retries — return a sanitized 502 while logging the inner exception
    logger.error("Retries exhausted for request %s %s: %s", request.method, request.url, traceback.format_exc())
    return _error_response(
        status_code=status.HTTP_502_BAD_GATEWAY,
        message="Upstream service temporarily unavailable; please retry later.",
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Catch-all - do NOT expose exc to the client. Log full traceback server-side.
    logger.exception("Unhandled exception handling request %s %s: %s", request.method, request.url, traceback.format_exc())
    return _error_response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, message="Internal server error")

# Synchronous wrappers with tenacity (called from threads)
@retry(
    reraise=True,
    stop=stop_after_attempt(_MAX_RETRIES),
    wait=_WAIT,
    retry=retry_if_exception(_should_retry),
)
def _retrieve_context_sync(vector_store: VectorStore, question: str, client: OpenAIClient, top_k: int):
    """Synchronous retrieval call wrapped with retries. Intended to be run in a thread."""
    return vector_store.similarity_search_text(question, client=client, top_k=top_k)


@retry(
    reraise=True,
    stop=stop_after_attempt(_MAX_RETRIES),
    wait=_WAIT,
    retry=retry_if_exception(_should_retry),
)
def _generate_answer_sync(openai_client: OpenAIClient, instructions: str, prompt: str, model: str, max_output_tokens: int, temperature: float):
    """Synchronous generation call wrapped with retries. Intended to be run in a thread."""
    return openai_client.generate_answer(
        instructions=instructions,
        prompt=prompt,
        model=model,
        max_output_tokens=max_output_tokens,
        temperature=temperature,
    )


# Async helpers calling the sync wrappers via threads
async def _retrieve_context(*, question: str, openai_client: OpenAIClient, vector_store: VectorStore, top_k: int) -> list[RetrievedChunk]:
    """Retrieve relevant document chunks for the question (with retries for transient failures)."""
    try:
        chunks = await asyncio.to_thread(_retrieve_context_sync, vector_store, question, openai_client, top_k)
        return chunks
    except RetryError as re:
        logger.error("Retries exhausted during retrieval: %s", re)
        # Do not expose internal exception text to the client
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Context retrieval failed after retries")
    except Exception as e:
        logger.exception("Error during context retrieval")
        # Sanitize for client
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Context retrieval failed") from e


async def _generate_answer(*, question: str, chunks: list[RetrievedChunk], openai_client: OpenAIClient, settings: Settings) -> str:
    """Generate an answer given the question and retrieved chunks (with retries for transient failures)."""
    if not chunks:
        context_prompt = "No context passages were retrieved. Answer conservatively."
    else:
        formatted_chunks = []
        for chunk in chunks:
            document = str(
                chunk.metadata.get("source_path")
                or chunk.metadata.get("document_id")
                or chunk.chunk_id,
            )
            formatted_chunks.append(
                f"{chunk.chunk_id} ({document}):\n{chunk.content.strip()}"
            )
        context_prompt = "\n\n".join(formatted_chunks)

    prompt = (
        "Context passages:\n"
        f"{context_prompt}\n\n"
        f"Question: {question}\n"
        "Respond with a factual answer that cites chunk identifiers in parentheses."
    )

    try:
        answer_text = await asyncio.to_thread(
            _generate_answer_sync,
            openai_client,
            settings.response_instructions,
            prompt,
            settings.response_model,
            settings.response_max_tokens,
            settings.response_temperature,
        )
        if not answer_text:
            raise RuntimeError("Empty response from OpenAI")
        return answer_text.strip()
    except RetryError as re:
        logger.error("Retries exhausted during generation: %s", re)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Generation failed after retries")
    except HTTPException:
        # propagate HTTPException unchanged
        raise
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Generation failed")
        # Sanitize for client
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Generation failed") from exc

# Helpers & deps used by endpoints
def _sources_from_chunks(chunks: list[RetrievedChunk]) -> list[SourceAttribution]:
    sources: list[SourceAttribution] = []
    for chunk in chunks:
        document = str(
            chunk.metadata.get("source_path")
            or chunk.metadata.get("document_id")
            or chunk.chunk_id,
        )
        sources.append(
            SourceAttribution(
                chunk_id=chunk.chunk_id,
                document=document,
                score=float(chunk.score),
            )
        )
    return sources

def get_settings_dep() -> Settings:
    return get_settings()

def get_vector_store_dep(settings: Settings = Depends(get_settings_dep)) -> VectorStore:
    return _get_vector_store_cached(settings)

def get_openai_client_dep(settings: Settings = Depends(get_settings_dep)) -> OpenAIClient:
    return _get_openai_client_cached(settings)

def get_user_service_dep() -> UserService:
    """Dependency to get UserService instance."""
    return UserService(get_database())

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    user_service: UserService = Depends(get_user_service_dep)
) -> UserResponse:
    """
    Dependency to get the current authenticated user.
    
    Validates the JWT token and returns the user information.
    Raises HTTPException if token is invalid or user not found.
    """
    token = credentials.credentials
    
    # Decode and validate token
    try:
        payload = decode_access_token(token)
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token decode error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    
    # Validate session exists
    user_id_from_session = await user_service.validate_session(token)
    if not user_id_from_session or user_id_from_session != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    user = await user_service.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )
    
    return UserResponse(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        department=user.department,
        phone_number=user.phone_number,
        created_at=user.created_at,
    )

def _error_payload(status_code: int, message: str, *, details: object | None = None) -> dict[str, object]:
    def _json_safe(value: object) -> object:
        if value is None:
            return None
        if isinstance(value, BaseModel):
            return value.model_dump()
        if isinstance(value, (set, tuple)):
            return [_json_safe(item) for item in value]
        if isinstance(value, dict):
            return {key: _json_safe(val) for key, val in value.items()}
        if isinstance(value, list):
            return [_json_safe(item) for item in value]
        try:
            json.dumps(value)
            return value
        except TypeError:
            return str(value)

    error: dict[str, object] = {
        "status": int(status_code),
        "message": str(message),
    }
    if details is not None:
        error["details"] = _json_safe(details)
    return {"error": error}


def _error_response(status_code: int, message: str, *, details: object | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=_error_payload(status_code, message, details=details),
    )


def _serialize_event(event_name: str, payload: dict) -> bytes:
    return (json.dumps({"event": event_name, "data": payload}) + "\n").encode("utf-8")

# Authentication Endpoints
@app.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    user_data: UserCreate,
    request: Request,
    user_service: UserService = Depends(get_user_service_dep)
):
    """
    Register a new user account.
    
    **Requirements:**
    - Email must end with @klu.ac.in
    - Password must be at least 8 characters with uppercase, lowercase, and digit
    - Phone number must be valid Indian format (10 digits or +91 followed by 10 digits)
    
    **Returns:**
    - Access token (JWT)
    - User information
    """
    try:
        # Get client info
        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host if request.client else None
        
        # Create user
        user_response, access_token = await user_service.create_user(
            user_data,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        logger.info(f"New user signed up: {user_response.email}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Signup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user account"
        ) from e


@app.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    request: Request,
    user_service: UserService = Depends(get_user_service_dep)
):
    """
    Login with email and password.
    
    **Returns:**
    - Access token (JWT) - use this in Authorization header as "Bearer <token>"
    - User information
    """
    try:
        # Get client info
        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host if request.client else None
        
        # Authenticate user
        user_response, access_token = await user_service.authenticate_user(
            credentials.email,
            credentials.password,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        logger.info(f"User logged in: {user_response.email}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Login failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        ) from e


@app.post("/logout", response_model=LogoutResponse)
async def logout(
    current_user: UserResponse = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    user_service: UserService = Depends(get_user_service_dep)
):
    """
    Logout the current user and invalidate their session.
    
    **Requires:** Valid Bearer token in Authorization header
    """
    try:
        token = credentials.credentials
        
        # Delete session
        was_logged_out = await user_service.logout_user(token)
        
        if not was_logged_out:
            logger.warning(f"Session not found for user: {current_user.email}")
        
        from datetime import datetime, timezone
        
        logger.info(f"User logged out: {current_user.email}")
        
        return LogoutResponse(
            message="Successfully logged out",
            logged_out_at=datetime.now(timezone.utc)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Logout failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        ) from e


@app.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: UserResponse = Depends(get_current_user)):
    """
    Get current user's profile information.
    
    **Requires:** Valid Bearer token in Authorization header
    """
    return current_user

# Endpoints 
@app.post("/ask", response_model=AskResponse)
async def ask_question(
    body: AskRequest,
    current_user: UserResponse = Depends(get_current_user),
    stream: bool = Query(False, description="Stream chunked progress events"),
    settings: Settings = Depends(get_settings_dep),
    vector_store: VectorStore = Depends(get_vector_store_dep),
    openai_client: OpenAIClient = Depends(get_openai_client_dep),
):
    """
    Ask a question and get an AI-generated answer with source citations.
    
    **Requires:** Valid Bearer token in Authorization header
    
    **Query Parameters:**
    - stream: Set to true to receive streaming responses
    
    **Returns:**
    - Answer with source attributions
    """
    logger.info(f"Question from user {current_user.email}: {body.question}")

    # Retrieve context with retries handled in the wrapper
    chunks = await _retrieve_context(
        question=body.question,
        vector_store=vector_store,
        openai_client=openai_client,
        top_k=settings.top_k,
    )

    if not stream:
        answer_text = await _generate_answer(
            question=body.question,
            chunks=chunks,
            openai_client=openai_client,
            settings=settings,
        )
        response = AskResponse(answer=answer_text, sources=_sources_from_chunks(chunks))
        return JSONResponse(status_code=status.HTTP_200_OK, content=response.model_dump())

    async def event_stream() -> AsyncIterator[bytes]:
        sources = _sources_from_chunks(chunks)
        yield _serialize_event(
            "context",
            {
                "question": body.question,
                "sources": [source.model_dump() for source in sources],
            },
        )

        try:
            answer_text = await _generate_answer(
                question=body.question,
                chunks=chunks,
                openai_client=openai_client,
                settings=settings,
            )
            yield _serialize_event(
                "answer",
                {
                    "answer": answer_text,
                    "sources": [source.model_dump() for source in sources],
                },
            )
        except HTTPException as exc:
            # exc.detail may be structured (dict/list) thanks to our handlers
            status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
            detail_payload = exc.detail

            if (
                isinstance(detail_payload, dict)
                and isinstance(detail_payload.get("error"), dict)
                and detail_payload["error"].get("message")
            ):
                error_block = detail_payload["error"]
                message = str(error_block.get("message", "Request failed"))
                details = error_block.get("details")
            elif isinstance(detail_payload, str) and detail_payload.strip():
                message = detail_payload.strip()
                details = None
            else:
                message = "Request failed"
                details = detail_payload

            yield _serialize_event(
                "error",
                _error_payload(
                    status_code,
                    message,
                    details=details,
                ),
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Streaming error")
            yield _serialize_event(
                "error",
                _error_payload(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "Internal streaming error",
                ),
            )

    return StreamingResponse(event_stream(), media_type="application/json")


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse(content={"status": "ok"}, status_code=status.HTTP_200_OK)


@app.get("/departments", status_code=status.HTTP_200_OK)
async def get_departments() -> JSONResponse:
    """
    Get list of available departments.
    
    **Public endpoint** - No authentication required.
    
    Returns:
        List of department codes
    """
    departments = [
        {"code": "CSE", "name": "Computer Science and Engineering"},
        {"code": "ECE", "name": "Electronics and Communication Engineering"},
        {"code": "CIVIL", "name": "Civil Engineering"},
        {"code": "MECH", "name": "Mechanical Engineering"},
        {"code": "BME", "name": "Biomedical Engineering"},
        {"code": "EEE", "name": "Electrical and Electronics Engineering"}
    ]
    return JSONResponse(content={"departments": departments}, status_code=status.HTTP_200_OK)


# manual test endpoint for general info
@app.get("/", response_class=JSONResponse)
async def root() -> JSONResponse:
    """Simple root endpoint with service info."""
    info = {
        "service": "Question Answering Service",
        "version": "1.0.0",
        "endpoints": {
            "/signup": "POST endpoint to create a new user account",
            "/login": "POST endpoint to authenticate and get token",
            "/logout": "POST endpoint to invalidate session",
            "/me": "GET endpoint to get current user profile (requires auth)",
            "/ask": "POST endpoint to ask a question (requires auth)",
            "/departments": "GET endpoint to list available departments (public)",
            "/health": "GET health check endpoint",
        },
    }
    return JSONResponse(content=info, status_code=status.HTTP_200_OK)