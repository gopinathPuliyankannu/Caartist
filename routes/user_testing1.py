from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWSError, jwt

from models.user import User, TokenData, userInDB, Token
from config.db import select_db
from schemas.user import serializeDict, serializeList
from bson.objectid import ObjectId
import array as arr

SECURITY_KEY = "7016ffcd5dc6a3284506505642da5b50e252516de714602d408346a731d755cd"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = 30

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

user = APIRouter()

headers = {'Content-type': 'application/json'}


async def decrypt_value(plain_value, hashed_value):
    return pwd_context.verify(plain_value, hashed_value)


async def get_hashed_value(value):
    return pwd_context.hash(value)


async def get_decrypt_value(value):
    return pwd_context.hash_needs_update(value)


async def get_user(email):
    # print(email)
    specific_user = serializeDict(select_db['User'].find_one(
        {"email": email}))
    return specific_user['email']
    # if email in select_db['User']:
    #     user_data = select_db['User'][email]
    #     return user_data(**user_data)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not decrypt_value(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, SECURITY_KEY, algorithm=ALGORITHM)
    return encode_jwt


async def get_current_user(token: str = Depends(oauth_2_scheme)):
    creditional_Exceptions = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                           detail="could not validate creditonals", headers={"www-Authenticate: Bearer"})
    try:
        payload = jwt.decode(token, SECURITY_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('sub')
        if email is None:
            raise creditional_Exceptions

        token_data = TokenData(email=email)

    except JWSError:
        raise creditional_Exceptions

    user = get_user(email=token_data.email)
    if user is None:
        raise creditional_Exceptions

    return user


async def get_current_active_user(current_user: userInDB = Depends(get_current_user)):
    if current_user.disbled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    return current_user


@user.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # user = authenticate_user(form_data.username, form_data.password)
    # if not user:
    #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
    #                         detail="in correct credtionals", headers={"www-Authenticate: Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)
    return {
        "access_token": access_token, "token_type": "bearer"
    }


@user.post("/signup")
async def Sign_up(user: User):
    update_user = user.model_copy()
    try:

        decrypt_email = await get_user(user.email)
        print(decrypt_email)
        if not decrypt_email:
            return {"status": "Ok", "message": "already signup"}

        update_user.disabled = False
        update_user.password = await get_hashed_value(update_user.password)
        # select_db.User.insert_one(dict(update_user))
        return {"status": "Ok", "message": user.email + " " + "is added Successfully"}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

#  = Depends(get_current_active_user)


@user.get("/login",)
async def login_User(user:  User):
    try:
        select_user = serializeDict(
            select_db['User'].find_one({"email": email}))
        raise HTTPException(
            status_code=status.HTTP_200_OK, detail=select_user)

    except JWSError:
        raise HTTPException(status_code=404,
                            detail="invlid token")
