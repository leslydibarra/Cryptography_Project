#Lesly D. Ibarra
#Final Project Cryto

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
from Crypto.Cipher import AES, PKCS1_OAEP

#create separate class for sender 
class Sender:
    def __init__(self):
        self.sender_private_key = None
        self.sender_public_key = None
        self.receiver_public_key = None
        self.message = None
        self.encrypted_key = None
        self.encrypted_message = None
        self.mac = None

    # Generate RSA public and private key 
    def generate_keys(self):
        key = RSA.generate(2048)

        # Export the private and public keys and write to designated created files
        self.sender_private_key = key.export_key()
        self.sender_public_key = key.publickey().export_key()
        with open("sender_private_key.pem", "wb") as file:
            file.write(self.sender_private_key)
        with open("sender_public_key.pem", "wb") as file:
            file.write(self.sender_public_key)

    #open message.txt file to read contents and set message
    def set_message(self, file_path):
        with open(file_path, "r") as file:
            self.message = file.read().encode()

    #encrypt
    def encrypt_message(self):
        with open("receiver_public_key.pem", "rb") as file:
            self.receiver_public_key = RSA.import_key(file.read())

        # Generate AES key using random package and encrypt in CBC mode
        aes_key = get_random_bytes(16)
        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        # Encrypt AES key w/ receiver RSA public key
        cipher_rsa = PKCS1_OAEP.new(self.receiver_public_key)
        self.encrypted_key = cipher_rsa.encrypt(aes_key)

        # Set padding to message to fix length error 
        padded_message = self._pad_message(self.message)
        self.encrypted_message = iv + cipher_aes.encrypt(padded_message)

    # Set padding to message to fix length error 
    def _pad_message(self, message):
        padding_length = AES.block_size - len(message) % AES.block_size
        padding = bytes([padding_length]) * padding_length
        return message + padding
    
    #sender writes all data transmitted in file
    def send_message(self):
        with open("Transmitted_Data", "wb") as file:
            file.write(base64.b64encode(self.encrypted_message) + b'\n')
            file.write(base64.b64encode(self.encrypted_key) + b'\n')
