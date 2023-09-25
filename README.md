# Flask API JWT access contro with pydantic, flasgger and MongoDB backend example


    started from this: https://github.com/Gimyk/Rest_API_Flask
    then slowly fixed/evolved to show:
    * tokenreq decorator function to secure routes
    * signup route: to get a username, email and password and store it in MongoDB
    * login route: to use the username and password values to get an access and a refresh JWT tokens
    * refresh route: when the short lived access JWT expires, use the refresh token to get a new one
    * unprotected route: to show a non protected route
    * protected rount: to show a protected route. you can access it after login, then after the access token expires, you can use the refresh route to get a new one
    Added several security related techniques.
                     
    As a demo it depends on an unprotected localhost:27017 mongodb backend

    The .env file sets needed environment variables. Please edit them to change token
    expiry times and secrets

    The pyproject.toml file lists prerequisites to be installed by poetry. run poetry install 
    to install all prerequisite libraries
    
    To work under gunicorn: install gunicorn with pip3 but within the poetry shell enviroment.
    To check issue a 'which gunicorn' and you should see it's in the .venv .
    To run it under the VSCode debugger you also need a launch.json such as:
    ```
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
```
Please note that using the simple RUN command will not launch gunicorn but werkzeug on port 5000