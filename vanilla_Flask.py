from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/', methods = ['GET', 'POST'])
def index():
    if (request.method =='POST'):
        value = request.get_json()
        return jsonify({"Yoh": value}), 201
    else:
        return jsonify({'Welcome': "This is the app"})

@app.route('/times/<string:name>', methods = ['GET'])
def getName(name):
    return jsonify({"yourname":name+'12'})


if __name__ == '__main__':
    app.run(debug=True)