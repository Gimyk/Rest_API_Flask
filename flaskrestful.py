from flask import Flask, request
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)

class HelloWorld(Resource):
    def get(self):
        return {'data': 'Hello'}
    
    def post(self):
        print(request)
        someJson = request.get_json()
        return{'data': someJson}, 201


class Manupulate(Resource):
    def get(self, num):
        return {'data': num*10}


api.add_resource(HelloWorld, '/')
api.add_resource(Manupulate, '/times/<int:num>')


if __name__ == "__main__":
    app.run(debug=True)