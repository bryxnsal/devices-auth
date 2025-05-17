from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import UnsupportedAlgorithm
import base64
import jwt
import datetime
from flask import jsonify
import os
from app.models import Device

def is_valid_public_key(public_key: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key.encode(),
            backend=default_backend()
        )
        
        if isinstance(public_key, rsa.RSAPublicKey):
            return True
            
    except (ValueError, UnsupportedAlgorithm) as e:
        return False
    
    return False

def verify_signature(message: str, signature: str, public_key: str) -> bool:
    try:
        pub_key = serialization.load_pem_public_key(
            public_key.encode()
        )
        pub_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        return False

def generate_jwt_token(device_id):
    payload = {
        'device_id': device_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=3600)
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm='HS256')

def validate_jwt_token(token: str):
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
        return payload['device_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
