import os
import base64
from datetime import datetime, timezone
from time import time as crrtime
from copy import deepcopy

from flask import Flask, jsonify, request, abort
from pyotp import TOTP
from cryptography.fernet import Fernet

import server_side_decrypt

private_key_pem = os.environ.get('PRIVATE_KEY')
public_key_pem = os.environ.get('PUBLIC_KEY')
content_length_limit = 1024

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = content_length_limit

def get_totp(args):
    secret_key = args['secret_key']
    offset = args['offset']

    try:
        totp = TOTP(secret_key)

        if offset == 0:
            code = totp.now()
        else:
            if isinstance(offset, str):
                try:
                    offset = int(offset)
                except ValueError:
                    abort(400, description='Invalid offset value. Offset value must be an integer')

            if not isinstance(offset, int):
                    abort(400, description='Invalid offset value. Offset value must be an integer')

            code = totp.at(crrtime() + offset)
    except (base64.binascii.Error, TypeError, ValueError):
        abort(400, description='Invalid secret key')
    return {'totp_code': str(code)}

def encrypt(args):
    try:
        secret_key = args['secret_key']
        base64.b32decode(secret_key, casefold=True)
    except base64.binascii.Error:
        abort(400, description='Invalid secret key')

    try:
        encryption_key = args['encryption_key'].encode()
    except AttributeError:
        abort(400, description='Invalid encryption key. Please provide a URL-safe base64-encoded and 32 bytes in length key')

    try:
        cipher = Fernet(encryption_key)
        encoded_text = cipher.encrypt(secret_key.encode())
        encoded_text_str = base64.b64encode(encoded_text).decode()
        return {'encrypted_secret':encoded_text_str}
    except Exception:
        app.logger.error(f'API error: Error when encrypting')
        abort(500, description='Error when encrypting')

def decrypt(args):
    encrypted_secret = args['secret_key']

    try:
        encrypted_bytes = base64.b64decode(encrypted_secret)
    except base64.binascii.Error:
        abort(400, description='The provided encrypted secret key is invalid')

    try:
        encryption_key = args['encryption_key'].encode()
    except AttributeError:
        abort(400, description='Invalid encryption key. Please provide a URL-safe base64-encoded and 32 bytes in length key')

    try:
        cipher = Fernet(encryption_key)
        decrypted_text = cipher.decrypt(encrypted_bytes)
        decrypted_secret_str = decrypted_text.decode()
        return {'decrypted_secret': decrypted_secret_str}
    except Exception:
        app.logger.error(f'API error: Error when decrypting')
        abort(500, description='Error when decrypting')

def get_decrypted_totp(args):
    temp_args = deepcopy(args)
    decrypted_secret = decrypt(args)['decrypted_secret']
    temp_args['secret_key'] = decrypted_secret
    return get_totp(temp_args)

def encrypt_message(message, args):
    try:
        encryption_key = args['encryption_key'].encode()
    except AttributeError:
        abort(400, description='Invalid encryption key. Please provide a URL-safe base64-encoded and 32 bytes in length key')

    try:
        cipher = Fernet(encryption_key)
        encoded_text = cipher.encrypt(str(message).encode())
        encoded_text_str = base64.b64encode(encoded_text).decode()
        return encoded_text_str
    except Exception:
        app.logger.error(f'API error: Error when encrypting')
        abort(500, description='Error when encrypting')

@app.route('/api', methods=['POST'])
def api():
    data = request.get_json()
    args = {}

    if request.content_type != 'application/json':
        abort(415, description="Unsupported Media Type. Please send 'application/json'.")

    if not data:
        abort(400, description='Invalid request')

    if 'action' not in data:
        abort(400, description='Missing \'action\' query parameter')

    action = data['action']

    if action == 'get_public_key':
        return jsonify({'error': 0, 'message': public_key_pem})

    if 'secret_key' not in data:
        abort(400, description='Missing \'secret_key\' query parameter')

    args['secret_key'] = data['secret_key']

    args['offset'] = data.get('offset', 0)

    action_list = {
        'get_totp': get_totp,
        'encrypt': encrypt,
        'get_decrypted_totp': get_decrypted_totp
    }

    execute_action = action_list.get(action)

    if not execute_action:
        abort(400, description='Invalid action')

    is_encrypted_message = 'encrypted_message' in data

    if action == 'encrypt' or action == 'get_decrypted_totp' or is_encrypted_message:
        if 'encryption_key' not in data:
            abort(400, description='Please provide encryption_key')
        args['encryption_key'] = data['encryption_key']

    if is_encrypted_message:
        list_of_encrypted_message = data['encrypted_message']
        
        if type(list_of_encrypted_message) != list:
            abort(400, description='\'encrypted_message\' requires a list of data containing the names of the parameters whose encrypted messages need to be decrypted')

        for item in list_of_encrypted_message:
            need_decrypt_item = args.get(item)
            
            if need_decrypt_item is None:
                continue

            args[item] = server_side_decrypt.decrypt(need_decrypt_item, private_key_pem)

        if list_of_encrypted_message[0] != 'return_raw_message':
            message = execute_action(args)
            encrypted_message = encrypt_message(message, args)
            return jsonify({'error': 0, 'message': encrypted_message, 'note':'Decrypt message using Fernet (or similar) with the decryption key being \'encryption_key\''})    

    message = execute_action(args)
    return jsonify({'error': 0, 'message': message})

@app.route('/health', methods=['GET'])
def health_check():
    try:
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': error.description}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': error.description}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed', 'message': error.description}), 405 

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': f'POST requests exceed {content_length_limit} bytes', 'message': error.description}), 413

@app.errorhandler(415)
def unsupported_media_type(error):
    return jsonify({'error': 'Unsupported Media Type', 'message': error.description}), 415

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal server error', 'message': error.description}), 500

@app.errorhandler(Exception)
def handle_exception(error):
    app.logger.error(f"Unhandled exception: {error}")
    return jsonify({'error': 'Something went wrong', 'message': f'{datetime.now(timezone.utc)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)