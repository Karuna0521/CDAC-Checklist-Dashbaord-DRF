import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

from ams.settings import FKEY

cipher = Cipher(algorithms.AES(FKEY), modes.ECB(), backend=default_backend())

def data_encrypt(**data):
    l = {}
    for keys in data:
         if type(data[keys]) != str:
              data[keys]=str(data[keys])
         
         encryptor = cipher.encryptor()
         padder = padding.PKCS7(algorithms.AES.block_size*4).padder()
         padded_plaintext = padder.update(data[keys].encode()) + padder.finalize()
         ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
         text = base64.b64encode(ciphertext)
         l.update({keys:text.decode()})
    return l


def data_decrypt(**data):
    l = {}
    for keys in data:
        try :
           decryptor = cipher.decryptor()
        #    print(keys)
           
           decrypted_padded_plaintext = decryptor.update(base64.b64decode(data[keys].encode())) + decryptor.finalize()
           
           # Removing padding
           unpadder = padding.PKCS7(algorithms.AES.block_size*4).unpadder()
           decrypted_plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
           text = decrypted_plaintext
           l.update({keys:text.decode()})
        except ValueError:
             print(keys)
    return l
