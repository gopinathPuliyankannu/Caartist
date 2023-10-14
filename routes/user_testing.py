from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
# from datetime import datetime, timedelta
# from jose import JWSError, jwt

from models.user import User, Forgot, Filter
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
    specific_user = serializeDict(select_db['User'].find_one(
        {"email": email}))
    return specific_user['email']


@user.get("/grocery")
async def find_all_grocery():
    # print(select_db.BlinkItGrocery.find())
    return serializeList(select_db.BlinkItGrocery.find())


@user.get("/HairCareandAccessory")
async def Filpkart_Hair_Care_and_Accessory():
    try:
        return serializeList(select_db.FilpkartHairCareandAccessory.find())
    except:
        raise HTTPException(status_code=404, detail="Item not found")


@user.get("/Beauty", status_code=200)
async def Flipkart_Beauty():
    try:
        return {"status": "Ok", "data": serializeList(select_db.FlipkartBeauty.find())}

    except:
        raise HTTPException(status_code=404, detail="Item not found")


@user.get("/AmazonCameraPhotography", status_code=200)
async def Amazon_Camera_Photography():
    try:
        return {"status": "Ok", "data": serializeList(select_db.AmazonCameraPhotography.find())}

    except:
        raise HTTPException(status_code=404, detail="Item not found")


@user.get("/AmazonElectronicAccessories", status_code=200)
async def Amazon_Electronic_Accessories():
    try:
        return {"status": "Ok", "data": serializeList(select_db.AmazonElectronicAccessories.find())}

    except:
        raise HTTPException(status_code=404, detail="Item not found")


@user.get("/AmazonCameraPhotography/{id}")
async def Amazon_Camera_Photography(id):
    try:

        return {"status": "Ok", "data": serializeDict(select_db.AmazonCameraPhotography.find_one(
            {"_id": ObjectId(id)}))}

    except:
        raise HTTPException(status_code=404, detail="Item not found")


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


@user.post("/login")
async def login_User(user: User):
    try:
        select_user = serializeDict(select_db['User'].find_one(
            {"email": user.email}))
        if user.email == select_user['email'] and user.password == select_user['password']:
            return {"status": "Ok", "data": serializeDict(select_db['User'].find_one(
                {"email": user.email}))}
        else:
            raise HTTPException(status_code=404,
                                detail="Invalid Creditional")

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail="Invalid Creditional")


@user.put("/forgot")
async def forgot_password(forgot: Forgot):
    try:
        (select_db['User'].find_one_and_update({"email": forgot.email}, {
            "$set": {"email": forgot.change_email}}))
        return {"status": "Ok", "data": "update successfuly"}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail="email not valid")


@user.get("/filter/{category}")
async def filter_User(category):
    try:
        filterOptions = select_db.AmazonGrocery.find({
            "$or": [
                {
                    "Category": {"$regex": category, '$options': 'i'}
                },
                {
                    "Product": {"$regex": category, '$options': 'i'}
                },
                {
                    "Brand": {"$regex": category, '$options': 'i'}
                },
                {
                    "Price": {"$regex": category}
                },
            ]
        })

        return {"status": "Ok", "data": serializeList(filterOptions)}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))

# sprint plan


@user.get("/global_filter/{category}")
async def global_filter(category):
    try:
        search_results = []
        collection_names = select_db.list_collection_names()
        for collection_name in collection_names:
            collection = select_db[collection_name]
            search_result = collection.find({
                "$or": [
                    {"Category": {"$regex": category, '$options': 'i'}},
                    {"Product": {"$regex": category, '$options': 'i'}},
                    {"Brand": {"$regex": category, '$options': 'i'}},
                    {"Price": {"$regex": category, '$options': 'i'}},
                ]
            })
            search_results.extend(serializeList(search_result))
        return {"status": "Ok", "data": search_results}
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


@user.post("/search")
async def search(filter: Filter):
    try:
        search_results = []
        collection_names = filter.Filter

        for collection_name in collection_names:
            collection = select_db[collection_name]
            search_result = collection.find({
                "$or": [
                    {"Category": {"$regex": filter.searchtext, '$options': 'i'}},
                    {"Product": {"$regex": filter.searchtext, '$options': 'i'}},
                    {"Brand": {"$regex": filter.searchtext, '$options': 'i'}},
                    {"Price": {"$regex": filter.searchtext, '$options': 'i'}},
                ]
            })
            search_results.extend(serializeList(search_result))
        searchedString = ""
        if len(search_results) > 0:
            searchedString = search_results
        else:
            searchedString = "No result found"

        return {"status": "Ok", "count": len(search_results), "data": searchedString}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))
