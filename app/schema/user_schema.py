from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from pydantic.generics import GenericModel
from typing import TypeVar, Generic
T = TypeVar("T")

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    # Password removed - will be set after email verification
    profile_url: Optional[str] = None
    about: Optional[str] = None

class UpdateUserRequest(BaseModel):
    name: Optional[str]
    password: Optional[str]
    profile_url: Optional[str] = None
    about: Optional[str] = None

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class UserData(BaseModel):
    id: str
    email: str
    name: str
    profile_url: str | None = None
    exp: int
    user_role: int


class ApiResponse(GenericModel, Generic[T]):
    statusCode: int
    message: str
    data: T


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    profile_url: str
    about: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
