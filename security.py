import hashlib
import os
import base64
import bcrypt
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def hash_password(password):
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        logging.debug(f"Hashed password for storage: {hashed.decode('utf-8')}")
        return hashed.decode('utf-8')
    except Exception as e:
        logging.error(f"Error hashing password: {str(e)}")
        raise

def verify_password(password, password_hash):
    try:
        result = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        logging.debug(f"Password verification result: {result}")
        return result
    except Exception as e:
        logging.error(f"Password verification error: {str(e)}")
        return False

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

def encrypt_file(data, aes_key):
    fernet = Fernet(base64.urlsafe_b64encode(aes_key))
    return fernet.encrypt(data)

def decrypt_file(encrypted_data, aes_key):
    fernet = Fernet(base64.urlsafe_b64encode(aes_key))
    return fernet.decrypt(encrypted_data)

def compute_file_hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()

def encrypt_key(aes_key, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_key(encrypted_key, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key