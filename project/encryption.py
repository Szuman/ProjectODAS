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
    # generate a random salt
    salt = os.urandom(AES.block_size)
    # print(type(salt))
    # generate a random iv
    iv = Random.new().read(AES.block_size)
    # print(type(iv))

    # use the Scrypt KDF to get a private key from the password
    private_key = PBKDF2(password, salt, 32, 1000)

    # pad text with spaces to be valid for AES CBC mode
    padded_text = pad(plain_text)
    
    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_CBC, iv)
    encryption = cipher_config.encrypt(padded_text)
    # print(type(encryption))

    cipher_text = bytes.decode(base64.b64encode(encryption))
    salt_str = bytes.decode(base64.b64encode(salt))
    iv_str = bytes.decode(base64.b64encode(iv))
    # return the encrypted text
    return salt_str + iv_str + cipher_text            

#    return {
#        'cipher_text': bytes.decode(base64.b64encode(encryption)),
#        'salt': bytes.decode(base64.b64encode(salt)),
#        'iv': bytes.decode(base64.b64encode(iv))
#    }
 
def decrypt(encr, password):
    # print(type(encr))
    # print(len(encr))
    # decode the dictionary entries from base64
    ssalt = bytes(encr[:24], 'utf-8')
    salt = base64.b64decode(ssalt)
    # print(len(salt))
    siv = bytes(encr[24:48], 'utf-8')
    iv = base64.b64decode(siv)
    # print(len(iv))
    senc = bytes(encr[48:], 'utf-8')
    enc = base64.b64decode(senc)
    # print(len(enc))
    # generate the private key from the password and salt
    private_key = PBKDF2(password, salt, 32, 1000)
    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_CBC, iv)

    # decrypt the cipher text
    decrypted = cipher.decrypt(enc)

    # unpad the text to remove the added spaces
    original = unpad(decrypted)

    return original

# password = input("Password: ")
    
#     # First let us encrypt secret message
# encrypted = encrypt("The secretest message", password)
# print(encrypted)
    
#     # Let us decrypt using our original password
# decrypted = decrypt(encrypted, password)
# print(bytes.decode(decrypted))