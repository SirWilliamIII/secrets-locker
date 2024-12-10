### Store secret
1. input a secret
2. secret is encrypted
3. encryption process generates three outputs:
	•	Ciphertext: The encrypted version of the secret.
	•	Initialization Vector (IV): A random value required for encryption.
	•	Tag: A cryptographic value that ensures data integrity.
4. Store the ciphertext, IV, and tag securely.

### Retrieve secret 
1. provide the previously stored ciphertext, IV, and tag


The app uses AES-GCM encryption ensuring:
	•	Confidentiality: The plaintext secret is converted into secure ciphertext.
	•	Integrity: The authentication tag ensures the data has not been tampered with.
	•	Uniqueness: The IV ensures different ciphertexts are generated for the same secret.