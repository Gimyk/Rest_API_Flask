""" tutorial on API / JWT """
import os
from datetime import datetime, timedelta
from functools import wraps

import jwt
from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidTokenError
from bson import ObjectId
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(
    app, resources={r"/*": {"origins": "*"}}
)  # in production restrict to known domain(s)
bcrypt = Bcrypt(app)

BCRYPT_PEPPER = os.environ.get("BCRYPT_PEPPER", "FosseMaicheNonCiSia")
JWT_SECRET = os.environ.get("JWT_SECRET", "LaFavaELaRava...")

mongo = MongoClient("localhost", 27017)
db = mongo["py_api"]  # py_api is the name of the db


def tokenReq(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            try:
                jwt.decode(
                    token, JWT_SECRET, algorithms=["HS256"]
                )  # specify the algorithm used for JWT
            except ExpiredSignatureError:
                return jsonify({"status": "fail", "message": "Token has expired"}), 401
            except DecodeError:
                return jsonify({"status": "fail", "message": "Token is malformed"}), 401
            except InvalidTokenError:
                return jsonify({"status": "fail", "message": "Token is invalid"}), 401
            except Exception as general_exception:
                return (
                    jsonify(
                        {
                            "status": "fail",
                            "message": f"An unexpected error occurred: {str(general_exception)}",
                        }
                    ),
                    401,
                )

            return f(*args, **kwargs)
        else:
            return (
                jsonify(
                    {"status": "fail", "message": "Authorization header is missing"}
                ),
                401,
            )

    return decorated


@app.route("/")
def func():
    """empty route returning a smiley just for fun"""
    return "😺", 200


# get all and insert one
@app.route("/todos", methods=["GET", "POST"])
def index():
    res = []
    code = 500
    status = "fail"
    message = ""
    try:
        if request.method == "POST":
            res = db["todos"].insert_one(request.get_json())
            if res.acknowledged:
                message = "item saved"
                status = "successful"
                code = 201
                res = {"_id": f"{res.inserted_id}"}
            else:
                message = "insert error"
                res = "fail"
                code = 500
        else:
            for r in db["todos"].find().sort("_id", -1):
                r["_id"] = str(r["_id"])
                res.append(r)
            if res:
                message = "todos retrieved"
                status = "successful"
                code = 200
            else:
                message = "no todos found"
                status = "successful"
                code = 200
    except Exception as ee:
        res = {"error": str(ee)}
    return jsonify({"status": status, "data": res, "message": message}), code


# get one and update one
@app.route("/delete/<item_id>", methods=["DELETE"])
@tokenReq
def delete_one(item_id):
    data = {}
    code = 500
    message = ""
    status = "fail"
    try:
        if request.method == "DELETE":
            res = db["todos"].delete_one({"_id": ObjectId(item_id)})
            if res:
                message = "Delete successfully"
                status = "successful"
                code = 201
            else:
                message = "Delete failed"
                status = "fail"
                code = 404
        else:
            message = "Delete Method failed"
            status = "fail"
            code = 404

    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message, "data": data}), code


# get one and update one
@app.route("/getone/<item_id>", methods=["GET", "POST"])
@tokenReq
def by_id(item_id):
    data = {}
    code = 500
    message = ""
    status = "fail"
    try:
        if request.method == "POST":
            res = db["todos"].update_one(
                {"_id": ObjectId(item_id)}, {"$set": request.get_json()}
            )
            if res:
                message = "updated successfully"
                status = "successful"
                code = 201
            else:
                message = "update failed"
                status = "fail"
                code = 404
        else:
            data = db["todos"].find_one({"_id": ObjectId(item_id)})
            data["_id"] = str(data["_id"])
            if data:
                message = "item found"
                status = "successful"
                code = 200
            else:
                message = "update failed"
                status = "fail"
                code = 404
    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message, "data": data}), code


@app.route("/signup", methods=["POST"])
def save_user():
    message = ""
    code = 500
    status = "fail"
    try:
        data = request.get_json()
        if "email" in data and "username" in data and "password" in data:
            count = db["users"].count_documents({"email": str(data["email"])})
            if count >= 1:
                message = "user with that email exists"
                code = 401
                status = "fail"
            else:
                # hashing the password so it's not stored in the db as it was
                data["password"] = bcrypt.generate_password_hash(
                    BCRYPT_PEPPER + data["password"]
                ).decode("utf-8")
                data["created"] = datetime.now()
                newdocument = {
                    "username": str(data["username"]),
                    "email": str(data["email"]),
                    "password": str(data["password"]),
                    "created_ts": str(data["created"]),
                }
                res = db["users"].insert_one(newdocument)
                if res.acknowledged:
                    status = "successful"
                    message = "user created successfully"
                    code = 201
                else:
                    status = "fail"
                    message = "There was an error inserting data into MongoDB"
                    code = 400
        else:
            status = "fail"
            message = "Please make sure all fields are in the data"
            code = 400
    except Exception as ex:
        message = f"{ex}"
        status = "fail"
        code = 500
    return jsonify({"status": status, "message": message}), code


@app.route("/login", methods=["POST"])
def login():
    message = ""
    res_data = {}
    code = 500
    status = "fail"
    try:
        data = request.get_json()
        user = db["users"].find_one({"email": f'{data["email"]}'})

        if user:
            user["_id"] = str(user["_id"])
            if user and bcrypt.check_password_hash(
                user["password"], BCRYPT_PEPPER + data["password"]
            ):
                time = datetime.utcnow() + timedelta(hours=24)
                token = jwt.encode(
                    {
                        "user": {
                            "email": f"{user['email']}",
                            "id": f"{user['_id']}",
                        },
                        "exp": time,
                    },
                    JWT_SECRET,
                )

                del user["password"]

                message = "user authenticated"
                code = 200
                status = "successful"
                res_data["token"] = token
                res_data["user"] = user

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
    return jsonify({"status": status, "data": res_data, "message": message}), code


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="8000")
