import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt(string, password):
    """ Returns an encrypted string
    
    Hashes the password with a key derivation function and encrypts the string 
    using fernet, a high level symmetric encryption algorithm.
    
    Args:
        string: A raw file to be encrypted
        password: A user password
    """
    string = bytes(string, encoding="UTF-8")
    password = bytes(password, encoding="UTF-8")
    salt = b"qldkfjsmflskdhgu"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    encrypted = f.encrypt(string)
    return encrypted


def decrypt(enc_string, password):
    """ Returns the decrypted string
    
    Hashes the password with a key derivation function and decrypts the string 
    using fernet.
    
    Args:
        enc_string: An encrypted file
        password: A user password
    """
    password = bytes(password, encoding="UTF-8")
    enc_string = bytes(enc_string, encoding="UTF-8")
    salt = b"qldkfjsmflskdhgu"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    decrypted = f.decrypt(enc_string)
    return decrypted.decode("UTF-8")
