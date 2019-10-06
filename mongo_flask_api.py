from flask import Flask, jsonify, request
from pymongo import MongoClient
import json
from bson import json_util, ObjectId

app = Flask(__name__)

mongo = MongoClient('mongodb://localhost:27017/py_api', 27017)
db = mongo.py_api

# get all and insert one
@app.route('/', methods=['GET', 'POST'])
def index():
    if (request.method == 'POST'):
        db.test.insert_one(request.get_json())
        return "", 201
    else:
        res = []
        for r in db.test.find():
            res.append(json.loads(json_util.dumps(r)))
        return jsonify({'data': res})

# get one and update one
@app.route('/<id>', methods=['GET', 'POST'])
def by_id(id):
    if (request.method == 'POST'):
        db.test.update_one({"_id": ObjectId(id)}, { "$set": request.get_json()})
        return "", 201
    else:
        res = []
        for r in db.test.find({"_id": ObjectId(id)}):
            res.append(json.loads(json_util.dumps(r)))
        return jsonify({'data': res}), 200
# get one and delet one
@app.route('/<id>', methods=['POST'])
def by_id(id):
    if (request.method == 'POST'):
        db.test.delete_one({"_id": ObjectId(id)})
        return "", 201
    else:
        return jsonify({"responce": "Must be post method"}), 404


if __name__ == '__main__':
    app.run(debug=True)


# >>> gen_time = datetime.datetime(2010, 1, 1)
# >>> dummy_id = ObjectId.from_datetime(gen_time)
# >>> result = collection.find({"_id": {"$lt": dummy_id}})

# for r in db.test.find():
#     r.pop('_id')
#     # res.append(r)
#     res.append({
#         "name": r['name'],
#         "id": r['age']

#         })
