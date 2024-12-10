import boto3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom


kms_client = boto3.client("kms", region_name="us-east-1")

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


kms_key_id = 'arn:aws:kms:us-east-1:058264264506:key/4658b1f4-5738-46e2-b923-291fe25e4260'

# Initialize AWS KMS client
kms_client = boto3.client("kms")

# Generate a Data Encryption Key (DEK)
response = kms_client.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
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
