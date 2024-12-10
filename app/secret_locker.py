from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom


class SecretKeeper:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: str) -> dict:
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return {"ciphertext": ciphertext, "iv": iv, "tag": encryptor.tag}

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()