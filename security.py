import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def hash_password(password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex()

def verify_password(password, password_hash):
    """Verify a password against its hash."""
    return hash_password(password) == password_hash

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt_file(data):
    key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encrypted_data = iv + ciphertext + encryptor.tag
    return encrypted_data, key

def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:12]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[12:-16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def compute_file_hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()

def encrypt_key(aes_key, public_key_pem):
    """Encrypt AES key with RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem)
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
    """Decrypt AES key with RSA private key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key