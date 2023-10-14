from pymongo import MongoClient


# connection_string = f"mongodb://localhost:27017/?retryWrites=true&w=majority"
connection_string = f"mongodb://10.10.10.19:27017/"
conn = MongoClient(connection_string)
select_db = conn["Caartist"]
select_fb_db = conn["flipkart_data"]
select_amazon_db = conn["amazon_data"]
