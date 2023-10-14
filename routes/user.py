from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWSError, jwt
from jose.exceptions import ExpiredSignatureError
from models.user import User, TokenData, Token, Filter, LoginUser, Forgot, addCart, UserRegistration, verifypasscode, AccessTokenData, Feedback
from config.db import select_db, select_fb_db, select_amazon_db, conn
from schemas.user import serializeDict, serializeList, ViewCartEntity
from bson.objectid import ObjectId
from pydantic import create_model
import httpx
import phonenumbers
import random
import firebase_admin
from firebase_admin import credentials, messaging


SECURITY_KEY = "7016ffcd5dc6a3284506505642da5b50e252516de714602d408346a731d755cd"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
# JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']   # should be kept secret
# JWT_REFRESH_SECRET_KEY = os.environ['JWT_REFRESH_SECRET_KEY']

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

user = APIRouter()

headers = {'Content-type': 'application/json'}

# Initialize Firebase Admin SDK
cred = credentials.Certificate('caartist-6208ad19f554.json')
firebase_admin.initialize_app(cred)


def get_hashed_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return pwd_context.verify(password, hashed_pass)


def get_user(email: str):
    specific_user = select_db['User'].find_one(
        {"email": email})
    return specific_user


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['password']):
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
    creditional_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="could not valid the creditonal",
                                          headers={"www-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECURITY_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise creditional_exception
        token_data = TokenData(email=username)

    except ExpiredSignatureError:
        raise creditional_exception
    # Handle the expired token error

    user = get_user(token_data.email)
    if user is None:
        raise creditional_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user['disabled']:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@user.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):

    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username and password",
                            headers={"www-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "Bearer"}


def insertone(payload: object):
    select_db.User.insert_one(dict(payload))


@user.post("/signup")
async def Sign_up(user: User):
    update_user = user.model_copy()
    try:
        get_email = get_user(user.email)
        if not get_email:
            update_user.disabled = False
            update_user.password = get_hashed_password(update_user.password)
            insertone(update_user)
            return {"status": status.HTTP_201_CREATED, "detail": user.email + " " + "is added Successfully"}
        return {"status": status.HTTP_404_NOT_FOUND, "message": user.email + " " + "is already added"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@user.post("/login")
async def login_User(user: LoginUser):
    try:
        selected_user = get_user(user.email)
        print(selected_user)
        if selected_user['disabled'] == True:
            return {"status": status.HTTP_400_BAD_REQUEST, "data": "Blocked Users"}

        if user.email == selected_user['email'] and verify_password(user.password, selected_user['password']):
            access_token_expires = timedelta(
                minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
            access_token = create_access_token(
                data={"sub": user.email}, expires_delta=access_token_expires)
            return {"status": status.HTTP_200_OK, "data": serializeDict(get_user(user.email)),   "access_token": access_token, "token_type": "bearer"}
        else:
            return {"status": status.HTTP_400_BAD_REQUEST, "detail": "Invalid Username or password"}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail="Invalid Username or password")


@user.get("/account/deactivation")
async def de_active_User(current_user: User = Depends(get_current_active_user)):
    try:
        selected_user = get_user(current_user['email'])
        if selected_user:
            select_db['User'].find_one_and_update({"email": selected_user['email']}, {
                "$set": {"disabled": True}})
            return {"status": status.HTTP_200_OK,
                    "message": "De-activated Successfully"}

        else:
            return {"status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid User"}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail="Invalid Creditionals")


@user.put("/forgot")
async def forgot_password(forgot: Forgot):
    try:
        (select_db['User'].find_one_and_update({"email": forgot.email}, {
            "$set": {"email": forgot.change_email}}))
        return {"status": "Ok", "data": "update successfuly"}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail="email not valid")


@user.get("/global_filter/{category}")
async def global_filter(category, current_user: User = Depends(get_current_active_user)):
    try:
        database_names = [select_db, select_amazon_db, select_fb_db]
        search_results = []
        for db_name in database_names:
            for collection_name in db_name.list_collection_names():
                collection = db_name[collection_name]
                results = collection.find({
                    "$or": [
                        {"product_name": {"$regex": f".*{category}.*", "$options": "i"}},
                        {"product_price": {"$regex": f".*{category}.*", "$options": "i"}},
                        # Add more fields as needed for your search
                    ]
                })
                search_results.extend(serializeList(results))
        return {"status": "Ok",
                "results": search_results
                }
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))

# check with latest DB


@user.post("/search")
async def search(filter: Filter, current_user: User = Depends(get_current_active_user)):
    try:
        search_results = []
        database_names = [select_db]
        search_results = []
        for db_name in database_names:
            for collection_name in db_name.list_collection_names():
                collection = db_name[collection_name]
                # query = {
                #     "$match": {
                #         "$or": [
                #             # Case-insensitive search
                #             {"product_name": {
                #                 "$regex": filter.searchtext, "$options": "i"}},
                #             {"product_price": {
                #                 "$regex": filter.searchtext, "$options": "i"}}
                #         ]

                #     }
                # }
                # sort_criteria = {
                #     "$sort": {
                #         "relevance_score": -1  # Sort in descending order of relevance_score
                #     }
                # }
                # print(collection)
                results = collection.find({
                    "$or": [
                        {"Product": {"$eq": filter.searchtext}},
                        {"Category": {"$eq": filter.searchtext}}
                        # Case-insensitive search
                        # {"product_name": {
                        #     "$regex": filter.searchtext, "$options": "i"}},
                        # {"product_price": {
                        #     "$regex": filter.searchtext, "$options": "i"}}
                    ]

                })

                # results = collection.aggregate([query, sort_criteria])
                search_results.extend(serializeList(results))
                print(len(search_results))

        searchedString = ""
        if len(search_results) > 0:
            searchedString = search_results
        else:
            searchedString = "No result found"

        return {"status": "Ok", "count": len(search_results), "data": searchedString}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


def addToCart(payload: object):
    select_db.Cart.insert_one(dict(payload))


def find_add_cart_filter(user_id):
    return select_db['Cart'].find_one({"user_id": user_id})

#  CAR-17


def insert_to_Recently_viewed(list, current_user):
    cart = select_db['Recently_viewed'].find_one(
        {"user_id": str(current_user['_id'])})

    if cart:

        for item in cart['items']:
            if item['_id'] == list['_id']:
                return {"status": status.HTTP_200_OK, "message": "already added"}

        select_db['Recently_viewed'].update_one(
            {'_id': cart['_id']},
            {'$push': {'items': list}})

    else:
        cart = {
            'user_id': str(current_user['_id']),
            'items': [list]
        }
        select_db['Recently_viewed'].insert_one(cart)


@user.post("/addCart")
async def add_cart(addCart: addCart, current_user: User = Depends(get_current_active_user)):
    update_user = addCart.model_copy()
    try:
        cart = find_add_cart_filter(str(current_user['_id']))

        if cart:
            for item in cart['items']:
                if item['item_id'] == update_user.id:
                    return {"status": status.HTTP_200_OK, "message": "already added"}

            # Update existing cart
            select_db['Cart'].update_one({'_id': cart['_id']},
                                         {'$push': {'items': {
                                             'item_id': update_user.id,
                                             'db_id': update_user.db,
                                             'Collection_id': update_user.collection,
                                         }}})

            # return {"status": status.HTTP_200_OK, "message": "cart added Successfully"}
        else:
            # Create a new cart if it doesn't exist
            cart = {
                'user_id': str(current_user['_id']),
                'items': [
                    {
                        'item_id': update_user.id,
                        'db_id': update_user.db,
                        'Collection_id': update_user.collection,

                    }
                ]
            }
            select_db['Cart'].insert_one(cart)
        return {"status": status.HTTP_200_OK, "message": "Cart added Successfully"}

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


@user.get("/ViewCart")
async def add_cart(current_user: User = Depends(get_current_active_user)):
    try:
        cart = find_add_cart_filter(str(current_user['_id']))
        if cart:
            return {
                "Status": status.HTTP_200_OK,
                "list": cart['items']
            }
        else:
            return {
                "Status": status.HTTP_200_OK,
                "list": []
            }
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


@user.get("/checkout")
async def checkout(current_user: User = Depends(get_current_active_user)):
    try:
        cart = find_add_cart_filter(str(current_user['_id']))
        if cart:
            return {
                "Status": status.HTTP_200_OK,
                "list": cart['items']
            }
        else:
            return {
                "Status": status.HTTP_200_OK,
                "list": []
            }
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


# CAR-17 end
query_params = {"page": (str, ""), "per_page": (str, "")}
query_model = create_model("Query", **query_params)


# car-18
@user.get("/Categories")
async def fetch_categories(params: query_model = Depends(), current_user: User = Depends(get_current_active_user)):
    try:
        params_as_dict = params.dict()
        start_list = (int(params.page) * int(params.per_page)) - \
            int(params.per_page)
        end_list = int((int(params.page) * int(params.per_page))/2)
        toalResult = []

        flipkart_collection_names = select_fb_db.list_collection_names()[
            start_list:end_list]
        amazon_collection_names = select_amazon_db.list_collection_names()[
            start_list:end_list]
        flipkart_count = len(select_fb_db.list_collection_names())
        Amazon_count = len(select_amazon_db.list_collection_names())
        totalCount = flipkart_count + Amazon_count

        for flipkart_collection in flipkart_collection_names:
            toalResult.append({
                "name": flipkart_collection,
                "type": "flipkart",
                "totalRecords": select_fb_db[flipkart_collection].count_documents({})
            })

        for amazon_collection in amazon_collection_names:
            toalResult.append({
                "name": amazon_collection,
                "type": "Amazon",
                "totalRecords": select_amazon_db[amazon_collection].count_documents({})
            })
        return {"details": params_as_dict, "list": toalResult, "total_Record": totalCount}
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))

query_catalog_params = {"id": (str, ""), "db": (
    str, ""), "Collection": (str, "")}
Catalog_Modal = create_model("Query", **query_catalog_params)


@user.get("/Catalog")
async def fetch_Catalog(params: Catalog_Modal = Depends(), current_user: User = Depends(get_current_active_user)):
    try:
        select_db_list = conn[params.db][params.Collection].find_one(
            {"_id": ObjectId(params.id)})
        select_db_list['db'] = params.db
        select_db_list['Collection'] = params.Collection
        select_db_list['timestamp'] = datetime.now()
        insert_to_Recently_viewed(select_db_list, current_user)
        # select_db.Recently_viewed.insert_one(dict(select_db_list))

        return {"status": status.HTTP_200_OK, "details": serializeDict(select_db_list)}
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


@user.get("/recentlyViewed")
async def recently_viewed(current_user: User = Depends(get_current_active_user)):
    try:
        recently_Viewed = select_db.Recently_viewed.find_one(
            {"user_id": str(current_user['_id'])})

        if recently_Viewed:
            return {
                "Status": status.HTTP_200_OK,
                "list": serializeList(recently_Viewed['items'])
            }
        else:
            return {
                "Status": status.HTTP_200_OK,
                "list": []
            }

    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


@user.get("/getProfile")
async def recently_viewed(current_user: User = Depends(get_current_active_user)):
    try:
        current_user_Details = {
            "_id": current_user["_id"],
            "email": current_user["email"],
            "first_Name": current_user["first_Name"],
            "last_Name": current_user["last_Name"],
        }

        return {"status": status.HTTP_200_OK, "details": serializeDict(current_user_Details)}
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))


# A dictionary to store phone number to verification code mappings
verification_codes = {}

# Function to generate a random 6-digit verification code


def generate_verification_code():
    return str(random.randint(100000, 999999))

# FastAPI route for sending the verification code


@user.post("/send-verification-code")
async def send_verification_code(user: UserRegistration):
    # Parse and validate the phone number
    try:
        parsed_number = phonenumbers.parse(user.phone_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            return {"message": "Invalid phone number."}

        formatted_number = phonenumbers.format_number(
            parsed_number, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.phonenumberutil.NumberFormatException:
        return {"message": "Invalid phone number."}

    # Generate a new verification code
    code = generate_verification_code()

    # Store the phone number and its verification code in the dictionary
    verification_codes[formatted_number] = code

    # In a real application, you would send the code via SMS to the user's phone number
    # Here, we'll just return the code for demonstration purposes
    return {"verification_code": code}


@user.post("/verify-verification-code")
async def verify_verification_code(user: verifypasscode):
    # Parse and validate the phone number
    try:
        parsed_number = phonenumbers.parse(user.phone_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            return {"message": "Invalid phone number."}

        formatted_number = phonenumbers.format_number(
            parsed_number, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.phonenumberutil.NumberFormatException:
        return {"message": "Invalid phone number."}

    # Check if the provided code matches the stored code
    stored_code = verification_codes.get(formatted_number)
    if stored_code and user.verification_code == stored_code:
        # Verification successful
        # In a real application, you would proceed with user registration
        return {"message": "Phone number verified successfully."}
    else:
        return {"message": "Invalid verification code."}


async def verify_facebook_access_token(token_data: AccessTokenData):
    verify_url = ""
    if (token_data.login_type == "gmail"):
        verify_url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token_data.access_token}"
    else:
        verify_url = f'https://graph.facebook.com/me?access_token={token_data.access_token}'

    #

    async with httpx.AsyncClient() as client:
        response = await client.get(verify_url)
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail='Invalid access token')
        user_data = response.json()
        user_name = serializeDict(user_data)['name']

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
        access_token = create_access_token(
            data={"sub": user_name}, expires_delta=access_token_expires)
        user_data['access_token'] = access_token
        user_data['token_type'] = 'Bearer'
        return user_data


@user.post('/socialMediaLogin')
async def facebook_login_callback(token_data: AccessTokenData = Depends(verify_facebook_access_token)):
    return {'message': "login successful", 'user_data': token_data}


# Function to send a notification
def send_notification(device_token, notification_data):
    message = messaging.Message(
        data=notification_data,
        token=device_token,
    )

    try:
        response = messaging.send(message)
        print("Notification sent successfully:", response)
    except Exception as e:
        print("Error sending notification:", e)


# Usage example
device_token = "fPnKRnG3TF69PfigUtkvvN:APA91bHuBnCFAJKUuk3W21Lh2WCIgDfmU9Ze9oIknBu2FnqynzGlqd8WdMr8JF-8M4KtzMm56WjLqZOd-3rkf8AnC76rvM7kemearzJzMKwIcO-RNhLw5LlxQk3br0GrDCQYiyosNDLE"
notification_data = {
    "title": "New Message",
    "body": "You have a new message!"
}


@user.get('/sendNotification')
async def facebook_login_callback():
    # You can now use token_data to authenticate or create a user in your system
    # Example: Check if the user is already registered in your database
    send_notification(device_token, notification_data)
    return {'message': "login successful"}


@user.post('/submitFeedback')
async def Submit_feedback(feedback: Feedback, current_user: User = Depends(get_current_active_user)):
    try:

        FeedbackForm = {
            "user_id": str(current_user['_id']),
            "comments": feedback.comments
        }
        select_db.Feedback.insert_one(FeedbackForm)
        return {'status': status.HTTP_200_OK, 'message': "feedback is successfully submitted"}
    except Exception as e:
        raise HTTPException(status_code=404,
                            detail=str(e))
