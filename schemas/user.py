def userEntity(item) -> dict:
    return {
        "id": str(item["_id"]),
        "Product": str(item["Product"]),
        "Brand": str(item["Brand"]),
        "Speciality": str(item["Speciality"]),
        # "Size": str(item["Size"]),
        # "Price": str(item["Price"])
    }


def usersEntity(entity) -> list:
    return [userEntity(item) for item in entity]


def serializeDict(a) -> dict:
    return {**{i: str(a[i]) for i in a if i == '_id'}, **{i: a[i] for i in a if i != '_id'}}


def serializeList(entity) -> list:
    return [serializeDict(a) for a in entity]


def ViewCartEntiry(item) -> dict:
    return {
        "id": str(item["_id"]),
        "userId": str(item["_id"]),
        "Product": str(item["Product"]),
        "Brand": str(item["Brand"]),
        "Category": str(item["Category"]),
        "Quantity": str(item["Quantity"]),
        "Price": int(item["Price"])
    }


def ViewCartEntity(entity) -> list:
    return [ViewCartEntiry(item) for item in entity]
