""" tutorial on API / JWT """
import os
from datetime import datetime, timedelta
from functools import wraps

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    DecodeError,
    InvalidTokenError,
    InvalidSignatureError,
    InvalidIssuerError,
)

from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(
    app, resources={r"/*": {"origins": "*"}}
)  # in production restrict to known domain(s)
bcrypt = Bcrypt(app)

BCRYPT_PEPPER = os.environ.get("BCRYPT_PEPPER")
JWT_SECRET = os.environ.get("JWT_SECRET")
ACCESS_TOKEN_LIFETIME = os.environ.get("ACCESS_TOKEN_LIFETIME")  # in MINUTES
REFRESH_TOKEN_LIFETIME = os.environ.get("REFRESH_TOKEN_LIFETIME")  # in DAYS

mongo = MongoClient("localhost", 27017)
db = mongo["py_api"]  # py_api is the name of the db


def tokenreq(funct):
    """decorator. applied to Flask route it will ensure it can be accessed only with valid JWT token
    provided in the "Authorization header of the request
    """

    @wraps(funct)
    def decorated(*args, **kwargs):
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            try:
                jwt.decode(
                    token, JWT_SECRET, algorithms=["HS256"]
                )  # specify the algorithm used for JWT
            except ExpiredSignatureError:
                return jsonify({"status": "fail", "message": "Token has expired"}), 401
            except InvalidSignatureError:
                return (
                    jsonify(
                        {"status": "fail", "message": "Signature verification failed"}
                    ),
                    401,
                )
            except InvalidIssuerError:
                return jsonify({"status": "fail", "message": "Invalid issuer"}), 401
            except DecodeError:
                print("Failed to decode token:", token)
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

            return funct(*args, **kwargs)
        else:
            return (
                jsonify(
                    {"status": "fail", "message": "Authorization header is missing"}
                ),
                401,
            )

    return decorated


@app.route("/signup", methods=["POST"])
def save_user():
    """will save the username, email, password and timestamp in mongodb"""
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
    except Exception as exception:
        message = f"{exception}"
        status = "fail"
        code = 500
    return jsonify({"status": status, "message": message}), code


@app.route("/login", methods=["POST"])
def login():
    """Check the provided email and password against saved values in MongoDB.
    If they are correct, it will return an access token and a refresh token in the response.
    Also deletes the password from the returned values.
    """
    message = ""
    res_data = {}
    code = 500
    status = "fail"
    try:
        data = request.get_json()
        user = db["users"].find_one({"email": f'{data["email"]}'})

        if user:
            user["_id"] = str(user["_id"])
            if bcrypt.check_password_hash(
                user["password"], BCRYPT_PEPPER + data["password"]
            ):
                # Generate Access Token
                access_exp_time = datetime.utcnow() + timedelta(
                    minutes=int(ACCESS_TOKEN_LIFETIME)
                )
                access_token = jwt.encode(
                    {
                        "user": {"email": f"{user['email']}", "id": f"{user['_id']}"},
                        "exp": access_exp_time,
                    },
                    JWT_SECRET,
                    algorithm="HS256",
                )

                # Generate Refresh Token
                refresh_exp_time = datetime.utcnow() + timedelta(
                    days=int(REFRESH_TOKEN_LIFETIME)
                )
                refresh_token = jwt.encode(
                    {
                        "user": {"email": f"{user['email']}", "id": f"{user['_id']}"},
                        "exp": refresh_exp_time,
                    },
                    JWT_SECRET,
                    algorithm="HS256",
                )
                del user["password"]
                message = "user authenticated"
                code = 200
                status = "successful"
                res_data["access_token"] = access_token
                res_data["refresh_token"] = refresh_token
                res_data["user"] = user
            else:
                message = "wrong password"
                code = 401
                status = "fail"
        else:
            message = "invalid login details"
            code = 401
            status = "fail"
    except Exception as exception:
        message = f"{exception}"
        code = 500
        status = "fail"
    return jsonify({"status": status, "data": res_data, "message": message}), code


@app.route("/refresh", methods=["POST"])
def refresh_token():
    """Refreshes an expired JWT and returns a new access token"""
    status = "fail"
    message = ""
    code = 500
    res_data = {}

    try:
        # Get the refresh token from the request
        data = request.get_json()
        refresh_token = data.get("refresh_token")

        # Decode and validate the refresh token
        decoded_data = jwt.decode(refresh_token, JWT_SECRET, algorithms=["HS256"])

        # If token is valid, issue a new access token
        new_expiry = datetime.utcnow() + timedelta(minutes=int(ACCESS_TOKEN_LIFETIME))
        new_token = jwt.encode(
            {
                "user": {
                    "email": decoded_data["user"]["email"],
                    "id": decoded_data["user"]["id"],
                },
                "exp": new_expiry,
            },
            JWT_SECRET,
            algorithm="HS256",
        )

        res_data["access_token"] = new_token
        status = "success"
        message = "Access token refreshed"
        code = 200

    except jwt.ExpiredSignatureError:
        message = "Refresh token has expired"
        code = 401
    except jwt.InvalidTokenError:
        message = "Invalid token"
        code = 401
    except Exception as e:
        message = f"An unexpected error occurred: {str(e)}"
        code = 500

    return jsonify({"status": status, "message": message, "data": res_data}), code


# simple routes to demostrate an unprotected and a protected (by the tokenreq decorator) route


@app.route("/")
def func():
    """unprotected route returning a smiley just for fun"""
    return "😺", 200


@app.route("/protected", methods=["GET"])
@tokenreq
def protected_route():
    """simple protected route"""
    return jsonify({"message": "You have access to this JWT protected resource."})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="8000")
