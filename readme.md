# Table of Contents

1. [Deployment](#1-deployment)  
2. [API Documentation](#2-api-documentation)  
   - 2.1. [Introduction](#21-introduction)  
   - 2.2. [Base URL](#22-base-url)  
   - 2.3. [Request Format](#23-request-format)  
   - 2.4. [Response Format](#24-response-format)  
   - 2.5. [Actions & Usage](#25-actions--usage)  
     - 2.5.1. [Get Public Key](#251-get-public-key)  
     - 2.5.2. [Get TOTP Code](#252-get-totp-code)
     - 2.5.3. [Encrypt Secret Key (AES)](#253-encrypt-secret-key-aes)
     - 2.5.4. [Get TOTP from an Encrypted Secret](#254-get-totp-from-an-encrypted-secret)
   - 2.6. [Handling Encrypted Parameters](#26-handling-encrypted-parameters-encrypted_message)
     - 2.6.1. [Purpose of encrypted_message](#261-purpose-of-encrypted_message)
     - 2.6.2. [Example Request with RSA-encrypted Parameters](#262-example-request-with-rsa-encrypted-parameters)
   - 2.7. [Encrypting API Response](#27-encrypting-api-response-encrypted_message-handling)  
   - 2.8. [Error Handling](#28-error-handling)  
3. [Appendix](#3-appendix)  
   - 3.1. [Generate Encryption Key Using Fernet](#31-generate-encryption-key-using-fernet)  
   - 3.2. [Message Encryption/Decryption Using Fernet](#32-message-endecryption-using-fernet)  
   - 3.3. [Encryption Using RSA Algorithm](#33-encryption-using-rsa-algorithm)  

# **1. Deployment**
Build command
   ```bash
   pip install -r requirements.txt
   ```
Start command
   ```bash
   gunicorn app:app
   ```

# **2. API Documentation**  

## 2.1. Introduction 
This API provides functionalities for **TOTP generation, encryption, and secure communication** using **RSA and AES encryption**. The API ensures data security by allowing encrypted input parameters and encrypted responses.  

---

## 2.2. Base URL  
```
http://<your-server-address>/api
```
All requests must be sent to this endpoint as **POST requests** with `Content-Type: application/json`.

---

## 2.3. Request Format 
- Requests must be **JSON-formatted**.  
- The `"action"` parameter is required to specify the desired operation.  
- If any parameters are **encrypted using RSA**, they must be listed in `"encrypted_message"`.  

**Example Request:**  
```json
{
    "action": "get_decrypted_totp",
    "secret_key": "<RSA_encrypted_secret_key>",
    "encryption_key": "<RSA_encrypted_encryption_key>",
    "offset": 0,
    "encrypted_message": ["secret_key", "encryption_key"]
}
```

---

## 2.4. Response Format 
- All responses are **JSON-formatted**.  
- If `"encrypted_message"` is not included, the response will be **encrypted using AES (Fernet encryption)**.  
- If `"encrypted_message": ["return_raw_message"]` is included, the response will be returned as **plaintext (unencrypted).**  

**Example Response (unencrypted - RAW):**  
```json
{
    "error": 0,
    "message": {
        "totp_code": "123456"
    }
}
```
**Example Response (encrypted - AES/Fernet):**  
```json
{
    "error": 0,
    "message": "<AES_encrypted_response>",
    "note": "Decrypt using Fernet with 'encryption_key'"
}
```

---

## 2.5. Actions & Usage

### 2.5.1 Get Public Key
Retrieve the **RSA public key** for encrypting sensitive data before sending it to the server.  

**Request:**  
```json
{
    "action": "get_public_key"
}
```  
**Response:**  
```json
{
    "error": 0,
    "message": "<RSA_public_key>"
}
```

---

### 2.5.2 Get TOTP Code
Generates a **TOTP (Time-based One-Time Password)** based on a given secret key.  

**Request:**  
```json
{
    "action": "get_totp",
    "secret_key": "<base32_secret>",
    "offset": 0
}
```  
**Response:**  
```json
{
    "error": 0,
    "message": {
        "totp_code": "123456"
    }
}
```

---

### 2.5.3 Encrypt Secret Key (AES) 
Encrypts a given secret key using **AES (Fernet encryption)**.  

**Request:**  
```json
{
    "action": "encrypt",
    "secret_key": "<base32_secret>",
    "encryption_key": "<base64_encoded_32_bytes_key>"
}
```  
**Response:**  
```json
{
    "error": 0,
    "message": {
        "encrypted_secret": "<AES_encrypted_secret>"
    }
}
```

---

### 2.5.4 Get TOTP from an Encrypted Secret  
Decrypts an **AES-encrypted secret key** and generates a **TOTP code**.  

**Request:**  
```json
{
    "action": "get_decrypted_totp",
    "secret_key": "<AES_encrypted_secret>",
    "encryption_key": "<base64_encoded_32_bytes_key>",
    "offset": 0
}
```  
**Response:**  
```json
{
    "error": 0,
    "message": {
        "totp_code": "123456"
    }
}
```

---

## 2.6. Handling Encrypted Parameters (`encrypted_message`)

### 2.6.1 Purpose of `encrypted_message`  
Some parameters are encrypted using **RSA** before sending them to the server. The `"encrypted_message"` array tells the server which parameters need **RSA decryption**.  

### 2.6.2 Example Request with RSA-encrypted Parameters 
**Client sends:**  
```json
{
    "action": "get_decrypted_totp",
    "secret_key": "<RSA_encrypted_secret_key>",
    "encryption_key": "<RSA_encrypted_encryption_key>",
    "offset": 0,
    "encrypted_message": ["secret_key", "encryption_key"]
}
```
**Server Processing:**  
1. **Detect `"encrypted_message"` array**.  
2. **Decrypt each parameter** using the **private RSA key (`private_key_pem`)**.  
3. **Process the request normally** after decryption.  

---

## 2.7. Encrypting API Response (`encrypted_message` Handling)

### 2.7.1 How It Works
- If `"encrypted_message"` is **not included**, the response will be **encrypted using AES (Fernet encryption)**.  
- If `"encrypted_message": ["return_raw_message"]` is included, the response will be returned **as plaintext (not encrypted).**  

### 2.7.2 Example Requests & Responses

**Client Request (for encrypted response - `"encrypted_message"` not included):**  
```json
{
    "action": "get_decrypted_totp",
    "secret_key": "<RSA_encrypted_secret_key>",
    "encryption_key": "<RSA_encrypted_encryption_key>",
    "offset": 0,
    "encrypted_message": ["secret_key", "encryption_key"]
}
```
**Server Response (AES-encrypted):**  
```json
{
    "error": 0,
    "message": "<AES_encrypted_response>",
    "note": "Decrypt using Fernet with 'encryption_key'"
}
```

**Client Request (for RAW response - `"return_raw_message"` included):**  
```json
{
    "action": "get_decrypted_totp",
    "secret_key": "<RSA_encrypted_secret_key>",
    "encryption_key": "<RSA_encrypted_encryption_key>",
    "offset": 0,
    "encrypted_message": ["return_raw_message", "secret_key", "encryption_key"]
}
```
**Server Response (RAW, not encrypted):**  
```json
{
    "error": 0,
    "message": {
        "totp_code": "123456"
    }
}
```

**Client Decryption Example (Python - for encrypted response):**  
See [Encryption](#Encryption)

---

## 2.8. Error Handling
All API errors return a JSON response with an `"error"` key.  

| Status Code | Meaning | Example Response |
|-------------|---------|-----------------|
| **400** | Bad Request | `{"error": "Bad request", "message": "Invalid offset value"}` |
| **404** | Not Found | `{"error": "Not found", "message": "Action not recognized"}` |
| **405** | Method Not Allowed | `{"error": "Method not allowed", "message": "Use POST requests only"}` |
| **415** | Unsupported Media Type | `{"error": "Unsupported Media Type", "message": "Use 'application/json'"}` |
| **500** | Internal Server Error | `{"error": "Internal server error", "message": "Unexpected error occurred"}` |

# **3. Appendix**
## 3.1 Generate encryption key using Fernet
1. Install the `cryptography` library if you haven't already:
   ```bash
   pip install cryptography
   ```

2. Once installed, you can generate a Fernet key using the following code:

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()

print(key.decode())
```
## 3.2 Message en/decryption using Fernet
### Encryption
The API supports encryption, however client-side encryption is possible.

```python
from cryptography.fernet import Fernet
import base64

def encrypt(message, encryption_key):
    cipher = Fernet(encryption_key.encode())

    encoded_text = cipher.encrypt(message.encode())

    encoded_text_str = base64.b64encode(encoded_text).decode()

    return encoded_text_str
```

### Decryption
The API does not support decryption for security reasons, decryption of encrypted messages sent from the server needs to be implemented on the client.

```python
from cryptography.fernet import Fernet
import base64

def decrypt(encrypted_message, decryption_key):
    encrypted_bytes = base64.b64decode(encrypted_message)

    cipher = Fernet(decryption_key)

    decrypted_message = cipher.decrypt(encrypted_bytes)

    decrypted_message_str = decrypted_message.decode()

    return decrypted_message_str
```

## 3.3 Encryption using RSA algorithm
### Generate private key and public key
For server administrators only

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

private_key_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_key = private_key.public_key()
public_key_str = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

print("Private key):")
print(private_key_str)

print("\nPublic key:")
print(public_key_str)
```

### Encrypt messages sent
This operation MUST be done on the client side (if encryption is required) before sending the message.

```python
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def encrypt(message, public_key_pem):
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
```