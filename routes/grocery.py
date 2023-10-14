from fastapi import APIRouter, HTTPException, Request

from config.db import select_db
from schemas.user import serializeDict, serializeList
from bson.objectid import ObjectId
user = APIRouter()


@user.get("/grocery")
async def find_all_users():
    # print(select_db.BlinkItGrocery.find())
    return serializeList(select_db.BlinkItGrocery.find())
