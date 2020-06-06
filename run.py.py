from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS
from bson import ObjectId
import json


app = Flask(__name__)
mongo = MongoClient('mongodb://localhost:27017/py_api', 27017)
cors = CORS(app, resources={r"/*": {"origins": "*"}})

db = mongo.py_api['test']

# get all and insert one
@app.route('/', methods=['GET', 'POST'])
def index():
    res = []
    code = 500
    try:
        if (request.method == 'POST'):
            res = db.insert_one(request.get_json())
            if res.acknowledged:
                res = 'successful'
                code = 201
            else:
                res = 'not found'
                code = 500

        else:
            res = []
            for r in db.find():
                r['_id'] = str(r['_id'])
                res.append(r)
            if res:
                code = 200
            else:
                code = 500
    except Exception as ee:
        res = {"error": str(ee)}
    return jsonify({'data': res}), code


# get one and update one
@app.route('/<id>', methods=['GET', 'POST'])
def by_id(id):
    res = []
    code = 500
    try:
        if (request.method == 'POST'):
            res = db.update_one({"_id": ObjectId(id)}, { "$set": request.get_json()})
            if res:
                code = 200
            else:
                code = 500
        else:
            res = {}
            res =  db.find_one({"_id": ObjectId(id)})
            res['_id'] = str(res['_id'])
            if res:
                code = 200
            else:
                code = 500
    except Exception as ee:
        res = {"error": str(ee)}

    return jsonify({'data': res}), code


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='8080')

