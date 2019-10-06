from pymongo import MongoClient

mongo = MongoClient('localhost', 27017)
db = mongo['py_api']
coll = db['test']


for x in coll.find():
    print(x)