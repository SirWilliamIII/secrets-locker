from flask import Flask, request, jsonify
from secret_locker import SecretKeeper

app = Flask(__name__)
# Replace with your actual 256-bit key or fetch from secure storage
secret_keeper = SecretKeeper(key=b"your-256-bit-key")


@app.route("/store", methods=["POST"])
def store_secret():
    secret = request.json.get("secret")
    encrypted = secret_keeper.encrypt(secret)
    return jsonify(encrypted)


@app.route("/retrieve", methods=["POST"])
def retrieve_secret():
    data = request.json
    secret = secret_keeper.decrypt(data["ciphertext"], data["iv"], data["tag"])
    return jsonify({"secret": secret})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
