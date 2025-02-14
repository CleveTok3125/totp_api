import base64

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def decrypt(ciphertext_str, private_key_pem):
    private_key = load_pem_private_key(private_key_pem.encode(), password=None)

    ciphertext = base64.b64decode(ciphertext_str)
    
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plaintext_str = plaintext.decode()

    return plaintext_str