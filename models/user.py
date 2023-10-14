from pydantic import BaseModel
from typing import Optional, Set, Union
from bson.objectid import ObjectId


class Forgot(BaseModel):
    email: str
    change_email: str


class Filter(BaseModel):
    # Filter: Set[str] = set()
    searchtext: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str or None = None


class User(BaseModel):
    email: str
    first_Name: str or None = None
    last_Name: str or None = None
    password: str
    disabled: Optional[bool] = None


class LoginUser(BaseModel):
    email: str
    password: str


class userInDB(BaseModel):
    hashed_password: str


class PostBaseSchema(BaseModel):
    userId: Optional[str] or None = None

    class Config:
        from_attributes = True
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class addCart(BaseModel):
    id: str
    db: str
    collection: str
    pass


class UserRegistration(BaseModel):
    phone_number: str


class verifypasscode(UserRegistration):
    verification_code: str
    pass


class AccessTokenData(BaseModel):
    access_token: str
    login_type: str


class Feedback(BaseModel):
    comments: str
