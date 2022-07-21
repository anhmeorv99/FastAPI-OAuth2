from datetime import datetime, timedelta

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Security, status

from sqlalchemy.orm import Session

from app.database import models
from app.database.crud import authenticate_user, get_current_active_user, get_current_user, get_user, \
    create_user as crud_create_user
from app.database.database import engine, get_db
from app.database.schemas import Token, OAuth2PasswordRequest, User, UserInDB
from app.settings import ACCESS_TOKEN_EXPIRE_MINUTES
from app.utils import create_access_token

models.Base.metadata.create_all(bind=engine)

app = FastAPI()


@app.post("/users/", response_model=User)
def create_user(user: UserInDB, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud_create_user(db=db, user=user)


@app.post("/token", response_model=Token)
async def login_for_access_token(data: OAuth2PasswordRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, data.username, data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"username": user.username, "scopes": data.scopes},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


# @app.get("/users/items/")
# async def read_own_items(
#         current_user: User = Security(get_current_active_user, scopes=["items"])
# ):
#     return [{"item_id": "Foo", "owner": current_user.username}]


# @app.get("/status/")
# async def read_system_status(current_user: User = Depends(get_current_user)):
#     return {"status": "ok"}


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8005)
