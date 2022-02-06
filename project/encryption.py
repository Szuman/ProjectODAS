# AES 256 encryption/decryption using pycrypto library
from Crypto.Protocol.KDF import PBKDF2
import base64
from Crypto.Cipher import AES
from Crypto import Random
import os

# pad with spaces at the end of the text
# beacuse AES needs 16 byte blocks
def pad(s):
    block_size = 16
    remainder = len(s) % block_size
    padding_needed = block_size - remainder
    return bytes(s + padding_needed * ' ', 'utf-8')

# remove the extra spaces at the end
def unpad(s): 
    return s.rstrip()
 
def encrypt(plain_text, password):
    salt = os.urandom(AES.block_size)
    iv = Random.new().read(AES.block_size)

    private_key = PBKDF2(password, salt, 32, 10000)

    padded_text = pad(plain_text)
    
    cipher_config = AES.new(private_key, AES.MODE_CBC, iv)
    encryption = cipher_config.encrypt(padded_text)

    cipher_text = bytes.decode(base64.b64encode(encryption))
    salt_str = bytes.decode(base64.b64encode(salt))
    iv_str = bytes.decode(base64.b64encode(iv))

    return salt_str + iv_str + cipher_text            

 
def decrypt(encr, password):
    ssalt = bytes(encr[:24], 'utf-8')
    salt = base64.b64decode(ssalt)

    siv = bytes(encr[24:48], 'utf-8')
    iv = base64.b64decode(siv)

    senc = bytes(encr[48:], 'utf-8')
    enc = base64.b64decode(senc)

    private_key = PBKDF2(password, salt, 32, 10000)

    cipher = AES.new(private_key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(enc)

    original = unpad(decrypted)

    return original
