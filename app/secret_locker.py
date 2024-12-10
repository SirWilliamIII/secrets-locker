import boto3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import dotenv

dotenv.load_dotenv()


class SecretLocker:
	def __init__(self, key: bytes):
		self.key = key

	def encrypt(self, plain_text: str) -> dict:
		iv = urandom(16)
		cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv))
		encryptor = cipher.encryptor()
		ciphertext = encryptor.update(plain_text.encode()) + encryptor.finalize()
		return {"ciphertext": ciphertext, "iv": iv, "tag": encryptor.tag}

	def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
		cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag))
		decryptor = cipher.decryptor()
		return (decryptor.update(ciphertext) + decryptor.finalize()).decode()


kms_key_id = os.getenv("KMS_KEY_ID")

# Ensure environment variables are set
if not all([os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY"), os.getenv("KMS_KEY_ID")]):
	raise EnvironmentError("Please set the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and KMS_KEY_ID environment variables.")

# Initialize AWS KMS client
kms_client = boto3.client(
	"kms",
	aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
	aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
	region_name="us-east-1"
)

# Generate a Data Encryption Key (DEK)
response = kms_client.generate_data_key(KeyId=os.getenv("KMS_KEY_ID"), KeySpec="AES_256")
dek_plaintext = response["Plaintext"]  # Use this for in-memory encryption
dek_ciphertext = response["CiphertextBlob"]  # Store this securely for later use

# Initialize the Secret Keeper with the plaintext DEK
secret_keeper = SecretLocker(key=dek_plaintext)

# Example usage
plaintext = "My super secret data"
encrypted = secret_keeper.encrypt(plaintext)
print("Encrypted data:", encrypted)

# To decrypt later, decrypt the encrypted DEK using KMS
dek_plaintext = kms_client.decrypt(CiphertextBlob=dek_ciphertext)["Plaintext"]
secret_keeper = SecretLocker(key=dek_plaintext)
decrypted = secret_keeper.decrypt(encrypted["ciphertext"], encrypted["iv"], encrypted["tag"])
print("Decrypted data:", decrypted)
