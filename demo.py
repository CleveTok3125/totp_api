from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import requests

from getpass import getpass
import base64, json

def key_generator():
	key = Fernet.generate_key()
	return key.decode()

def fernet_encrypt(message, encryption_key):
	cipher = Fernet(encryption_key.encode())

	encoded_text = cipher.encrypt(message.encode())

	encoded_text_str = base64.b64encode(encoded_text).decode()

	return encoded_text_str

def fernet_decrypt(encrypted_message, decryption_key):
	encrypted_bytes = base64.b64decode(encrypted_message)

	cipher = Fernet(decryption_key)

	decrypted_message = cipher.decrypt(encrypted_bytes)

	decrypted_message_str = decrypted_message.decode()

	return decrypted_message_str

def get_public_key_pem(api):
	response = requests.post(api, json={'action':'get_public_key'}).text
	
	json_response = json.loads(response)
	public_key = json_response['message']
	return public_key

def rsa_encrypt(message, public_key_pem):
	public_key = load_pem_public_key(public_key_pem.encode())

	ciphertext = public_key.encrypt(
		message.encode(),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	ciphertext_base64 = base64.b64encode(ciphertext)
	ciphertext_str = ciphertext_base64.decode()

	return ciphertext_str

if __name__ == '__main__':
	api = input('API: ').strip()
	secret_key = getpass('Secret key: ').strip()

	if secret_key == '':
		secret_key = 'JBSWY3DPFQQFO33SNRSCC==='

	encryption_key = key_generator()
	#print(encryption_key)
	encrypted_secret_key = fernet_encrypt(secret_key, encryption_key)

	public_key_pem = get_public_key_pem(api)
	encrypted_encryption_key = rsa_encrypt(encryption_key, public_key_pem)

	print(f'\nEncrypted secret key: {encrypted_secret_key}\n')
	print(f'Encrypted encryption key: {encrypted_encryption_key}\n')

	if input('Check it out? (y/N) ').lower() == 'y':
		response = requests.post(api, json={
			'action':'get_decrypted_totp',
			'secret_key': encrypted_secret_key,
			'encryption_key': encrypted_encryption_key,
			'encrypted_message': ['encryption_key']
			})
		encrypted_response = response.text
		print('Encrypted response:', encrypted_response)

		if input('\nDecrypt it? (y/N) ').lower() == 'y':
			response_json = json.loads(encrypted_response)
			response_text = fernet_decrypt(response_json['message'], encryption_key)
			response_json['message'] = json.loads(response_text)
			print(json.dumps(response_json, indent=4))