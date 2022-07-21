from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi import Depends, HTTPException, Security, status

from sqlalchemy.orm import Session

from app.database import models
from app.database import schemas
from app.settings import SECRET_KEY, ALGORITHM
from app.utils import verify_password, get_password_hash

from jose import JWTError, jwt
from pydantic import BaseModel, ValidationError

from database.database import get_db

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "me": "Read information about the current user.",
        "items": "Read items."
    }
)

oauth2_code_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl='https://gitter.im/tiangolo/fastapi?at=5ee7e16f013105125a38d764',
    tokenUrl="token",
    scopes={"me": "Read information about the current user.", "items": "Read items."}
)


def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


async def get_current_user(
        security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = schemas.TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
        current_user: schemas.User = Security(get_current_user, scopes=["me"])
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def create_user(db: Session, user: schemas.UserInDB):
    password = get_password_hash(user.password)
    db_user = models.User(
        name=user.name,
        username=user.username,
        password=password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
