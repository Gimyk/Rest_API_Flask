from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS 
from bson import ObjectId
import json
import jwt
from datetime import datetime, timedelta


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
secret = "***************"

mongo = MongoClient('localhost', 27017)
db = mongo['py_api'] #py_api is the name of the db

def tokenReq(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            try:
                jwt.decode(token, secret)
            except:
                return jsonify({"status": "fail", "message": "unauthorized"}), 401
            return f(*args, **kwargs)
        else:
            return jsonify({"status": "fail", "message": "unauthorized"}), 401
    return decorated


# get all and insert one
@app.route('/todos', methods=['GET', 'POST'])
def index():
    res = []
    code = 500
    status = "fail"
    message = ""
    try:
        if (request.method == 'POST'):
            res = db.insert_one(request.get_json())
            if res.acknowledged:
                message = "item saved"
                status = 'successful'
                code = 201
                res = "ok"
            else:
                message = "insert error"
                res = 'fail'
                code = 500
        else:
            for r in db.find():
                r['_id'] = str(r['_id'])
                res.append(r)
            if res:
                message = "todos retrieved"
                code = 200
            else:
                code = 500
    except Exception as ee:
        res = {"error": str(ee)}
    return jsonify({"status":status,'data': res, "message":message}), code

# get one and update one
@app.route('/getone/<id>', methods=['GET', 'POST'])
@tokenReq
def by_id(item_id):
    data = {}
    code = 500
    message = ""
    status = "fail"
    try:
        if (request.method == 'POST'):
            res = db.update_one({"_id": ObjectId(item_id)}, { "$set": request.get_json()})
            if res:
                message = "updated successfully"
                status = "ok"
                code = 201
            else:
                message = "update failed"
                status = "fail"
                code = 404
        else:
            data =  db.find_one({"_id": ObjectId(item_id)})
            data['_id'] = str(data['_id'])
            if data:
                message = "item found"
                status = "successful"
                code = 200
            else:
                message = "update failed"
                status = "fail"
                code = 404
    except Exception as ee:
        res = {"error": str(ee)}

    return jsonify({"status": status, "message":message,'data': data}), code

@app.route('/signup', methods=['POST'])
def save_user():
    message = ""
    code = 500
    status = "fail"
    try:
        data = request.get_json()
        check = db['users'].find({"email": data['email']})
        if check.count() >= 1:
            message = "user with that email exists"
            code = 401
            status = "fail"

        # hashing the password so it's not stored in the db as it was 
        data['password'] = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        data['created'] = datetime.now()

        #this is bad practice since the data is not being checked before insert
        res = db["users"].insert_one(data) 
        if res.acknowledged:
            status = "successful"
            message = "user created successfully"
            code = 201
    except Exception as ex:
        message = f"{ex}"
        status = "fail"
        code = 500
    return jsonify({'status': status, "message": message}), 200

@app.route('/login', methods=['POST'])
def login():
    message = ""
    data = {}
    code = 500
    status = "fail"
    try:
        data = request.get_json()
        user = db['users'].find_one({"email": f'{data["email"]}'})

        if user:
            user['_id'] = str(user['_id'])
            if user and bcrypt.check_password_hash(user['password'], data['password']):
                time = datetime.utcnow() + timedelta(hours=24)
                token = jwt.encode({
                        "user": {
                            "email": f"{user['email']}",
                            "id": f"{user['_id']}",
                        },
                        "exp": time
                    },secret)

                del user['password']

                message = f"user authenticated"
                code = 200
                status = "successful"
                data['token'] = token.decode('utf-8')
                data['user'] = user

            else:
                message = "wrong password"
                code = 401
                status = "fail"
        else:
            message = "invalid login details"
            code = 401
            status = "fail"

    except Exception as ex:
        message = f"{ex}"
        code = 500
        status = "fail"
    return jsonify({'status': status, "data": data, "message":message}), code

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='8080')

