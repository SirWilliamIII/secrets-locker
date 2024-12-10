from flask import Flask, request, jsonify, render_template
from secret_locker import SecretLocker
import boto3
import os
from dotenv import load_dotenv
import base64

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

# Initialize AWS KMS client
kms_client = boto3.client(
    "kms",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION")
)

port = int(os.getenv("PORT", 5000))

# Fetch the KMS Key ID from the environment variable
kms_key_id = os.getenv("KMS_KEY_ID")
if not kms_key_id:
    raise EnvironmentError("KMS_KEY_ID environment variable is not set")

# Generate a Data Encryption Key (DEK) using AWS KMS
response = kms_client.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
dek_plaintext = response["Plaintext"]  # Use this key for encryption/decryption
dek_ciphertext = response["CiphertextBlob"]  # Store this securely for later use

# Initialize the SecretKeeper with the plaintext DEK
secret_keeper = SecretLocker(key=dek_plaintext)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/retrieve", methods=["POST"])
def retrieve_secret():
    data = request.json
    try:
        # Decode base64 strings into bytes
        ciphertext = base64.b64decode(data["ciphertext"])
        iv = base64.b64decode(data["iv"])
        tag = base64.b64decode(data["tag"])

        secret = secret_keeper.decrypt(ciphertext, iv, tag)
        return jsonify({"secret": secret})
    except KeyError as e:
        return jsonify({"error": f"Missing parameter: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


@app.route("/store", methods=["POST"])
def store_secret():
    secret = request.json.get("secret")
    if not secret:
        return jsonify({"error": "Secret is required"}), 400

    encrypted = secret_keeper.encrypt(secret)
    # Convert bytes to base64-encoded strings
    encrypted_base64 = {
        "ciphertext": base64.b64encode(encrypted["ciphertext"]).decode("utf-8"),
        "iv": base64.b64encode(encrypted["iv"]).decode("utf-8"),
        "tag": base64.b64encode(encrypted["tag"]).decode("utf-8"),
    }
    return jsonify(encrypted_base64)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
