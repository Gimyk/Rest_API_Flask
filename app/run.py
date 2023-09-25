# pylint: disable=broad-exception-caught
""" tutorial on Flask API / JWT / MongoDB backend
    started from this: https://github.com/Gimyk/Rest_API_Flask
    then slowly fixed/evolved to show:
    tokenreq decorator function to secure routes
    signup route: to get a username, email and password and store it in MongoDB
    login route: to use the username and password values to get an access and a refresh JWT tokens
    refresh route: when the short lived access JWT expires, use the refresh token to get a new one
    unprotected route: to show a non protected route
    protected rount: to show a protected route. you can access it after login, then after the access token
                     expires you can use the refresh route to get a new one
    Added several security related techniques.
                     
    As a demo it depends on an unprotected localhost:27017 mongodb
    The .env file sets needed environment variables
    The pyproject.toml file lists prerequisites to be installed by poetry 
    
    To work under gunicorn install it with pip3 but within the poetry shell enviroment
    To check issue a 'which gunicorn' and you should see it's in the .venv
    In a docker it's poetry run python -m gunicorn that will work hence the gunicorn library
        and not the apt installed binary
    To run it under the VSCode debugger you need a launch.json such as:
    {
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Flask",
            "type": "python",
            "request": "launch",
            "program": "/Users/bob/code/Rest_API_Flask/.venv/bin/gunicorn",
            "gevent": true,
            "args": ["app.run:app", "--bind=127.0.0.1:8000", "--reload", "-w", "4"]
        }
    ]
}
Please note that using the simple RUN command will not launch gunicorn but werkzeug on port 5000
"""
import os
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)
from pydantic import BaseModel, EmailStr, ValidationError, Field
from pymongo import MongoClient
from flasgger import Swagger

app = Flask(__name__)
swagger = Swagger(app)  # flasgger

CORS(
    app, resources={r"/*": {"origins": "*"}}
)  # in production restrict to known domain(s)
bcrypt = Bcrypt(app)

BCRYPT_PEPPER = os.environ.get("BCRYPT_PEPPER")
JWT_SECRET = os.environ.get("JWT_SECRET")
ACCESS_TOKEN_LIFETIME = os.environ.get("ACCESS_TOKEN_LIFETIME")  # in MINUTES
REFRESH_TOKEN_LIFETIME = os.environ.get("REFRESH_TOKEN_LIFETIME")  # in DAYS

MONGO_URI = os.environ.get("MONGO_URI")
mongo = MongoClient(MONGO_URI)
db = mongo["jwt_api"]  # py_api is the name of the db


class SignupModel(BaseModel):
    """pydantic model for user registration"""

    email: EmailStr
    username: str = Field(..., max_length=30)  # ... means field is required
    password: str = Field(..., max_length=30)


class LoginModel(BaseModel):
    """pydantic model for login"""

    email: EmailStr
    password: str = Field(..., max_length=30)


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
    """
    Will save the username, email, password, and timestamp in MongoDB.
    ---
    tags:
      - User management
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: Unique email address.
            username:
              type: string
              description: Desired username.
              minLength: 1
              maxLength: 30
            password:
              type: string
              description: Secure password.
              minLength: 1
              maxLength: 30
    responses:
      201:
        description: User successfully created.
      400:
        description: Bad request. There was a validation error or a data insertion error.
      401:
        description: Unauthorized. User with that email already exists.
      500:
        description: Internal Server Error. An unexpected error occurred during signup.
    """
    message = ""
    code = 500
    status = "fail"

    try:
        # Validate and parse incoming data using Pydantic
        model = SignupModel.model_validate(request.get_json())
        data = model.model_dump()
        count = db["users"].count_documents({"email": data["email"]})
        if count >= 1:
            message = "User with that email exists"
            code = 401
            status = "fail"
        else:
            hashed_password = bcrypt.generate_password_hash(
                BCRYPT_PEPPER + data["password"]
            ).decode("utf-8")
            created_ts = datetime.now()

            newdocument = {
                "username": data["username"],
                "email": data["email"],
                "password": hashed_password,
                "created_ts": created_ts,
            }

            res = db["users"].insert_one(newdocument)
            if res.acknowledged:
                status = "successful"
                message = "User created successfully"
                code = 201
            else:
                status = "fail"
                message = "There was an error inserting data into MongoDB"
                code = 400

    except ValidationError as exception:
        message = str(exception)
        status = "fail"
        code = 400
    except Exception as exception:
        message = str(exception)
        status = "fail"
        code = 500

    return jsonify({"status": status, "message": message}), code


@app.route("/login", methods=["POST"])
def login():
    """Check the provided email and password against saved values in MongoDB.
    If they are correct, it will return an access token and a refresh token in the response.
    Also deletes the password from the returned values.
    ---
    tags:
      - JWT management
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: Unique email address.
            password:
              type: string
              description: Secure password.
              minLength: 1
              maxLength: 30
    responses:
      200:
        description: User successfully authenticated. Returns access and refresh tokens.
      401:
        description: Unauthorized. Invalid login details or wrong password.
      500:
        description: Internal Server Error. An unexpected error occurred during login.
    """
    message = ""
    res_data = {}
    code = 500
    status = "fail"
    try:
        model = LoginModel.model_validate(request.get_json())
        data = model.model_dump()
        user = db["users"].find_one({"email": f"{data['email']}"})

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
                refresh_token_value = jwt.encode(
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
                res_data["refresh_token"] = refresh_token_value
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
    """Refreshes an expired JWT and returns a new access token.
    ---
    tags:
      - JWT management
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            refresh_token:
              type: string
              description: The refresh token issued during successful login.
    responses:
      200:
        description: Access token successfully refreshed.
      401:
        description: Unauthorized. Either the refresh token has expired or it's invalid.
      500:
        description: Internal Server Error. An unexpected error occurred during token refresh.
    """
    status = "fail"
    message = ""
    code = 500
    res_data = {}

    try:
        # Get the refresh token from the request
        data = request.get_json()
        refresh_token_value = data.get("refresh_token")

        # Decode and validate the refresh token
        decoded_data = jwt.decode(refresh_token_value, JWT_SECRET, algorithms=["HS256"])

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
    except Exception as exception:
        message = f"An unexpected error occurred: {str(exception)}"
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
    # app.run(debug=True, host="0.0.0.0", port="8000")  # werkzeug for development
    app.run()  # trying gunicorn -w 4 run:app (but does not find libraries)
