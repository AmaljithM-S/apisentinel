"""Registration and login."""


import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import User
from app.db.session import get_db
from app.rate_limit import limiter
from app.schemas import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.security import create_access_token, current_user, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("apisentinel.auth")


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register(
    request: Request,
    payload: RegisterRequest = Body(...),
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role="analyst",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Same message as wrong password -> prevents account enumeration
        raise HTTPException(status.HTTP_409_CONFLICT, "That email address cannot be registered")

    db.refresh(user)
    return TokenResponse(access_token=create_access_token(user), user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenResponse)
@limiter.limit("20/minute")
def login(
    request: Request,
    payload: LoginRequest = Body(...),
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email.lower()).one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account is disabled")
    return TokenResponse(access_token=create_access_token(user), user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> UserOut:
    return UserOut.model_validate(user)
