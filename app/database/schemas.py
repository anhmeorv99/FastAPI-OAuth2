from typing import List, Union
from pydantic import BaseModel


class OAuth2PasswordRequest(BaseModel):
    username: str
    password: str
    scopes: List[str] = []


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None
    scopes: List[str] = []


class User(BaseModel):
    name: str
    username: str
    disabled: Union[bool, None] = None


class UserInDB(User):
    password: str


class OAuth2Client(BaseModel):
    client_id: str
    client_secret: str
    scope: str
    grant_types: List[str]
    access_token_expiration: int
