#Lesly D. Ibarra
#Final Project Cryto

from Crypto.PublicKey import RSA
import base64
from sender import Sender
from Crypto.Cipher import AES, PKCS1_OAEP

#create separate class for receiver
class Receiver:
    def __init__(self):
        self.receiver_private_key = None
        self.receiver_public_key = None
        self.message = None
        self.encrypted_key = None
        self.encrypted_message = None
        self.mac = None

    #generate the RSA public and private key for receiver
    def generate_keys(self):
        key = RSA.generate(2048)
        self.receiver_private_key = key.export_key()
        self.receiver_public_key = key.publickey().export_key()

        # Write keys to designated files
        with open("receiver_private_key.pem", "wb") as file:
            file.write(self.receiver_private_key)
        with open("receiver_public_key.pem", "wb") as file:
            file.write(self.receiver_public_key)

    #decrypt message by reading receiver private key 
    def decrypt_message(self):
        with open("receiver_private_key.pem", "rb") as file:
            self.receiver_private_key = RSA.import_key(file.read() )

        # Decrypt AES key from sender and IV get
        cipher_rsa = PKCS1_OAEP.new(self.receiver_private_key)
        aes_key = cipher_rsa.decrypt(self.encrypted_key)
        iv = self.encrypted_message[:AES.block_size]
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        # fix padding block size to fix error 
        decrypted_message = self._depad_message(cipher_aes.decrypt (self.encrypted_message [AES.block_size:]) )
        self.message = decrypted_message.decode("utf-8") #use UTF-8

    #data received in Transmitted Data
    def receive_message_data(self):
        with open("Transmitted_Data", "rb") as file:
            self.encrypted_message = base64.b64decode(file.readline())
            self.encrypted_key = base64.b64decode(file.readline())

    #fix padding again for error
    def _depad_message(self, padded_message):
        padding = padded_message[-1]
        return padded_message[:-padding] 





#test programs by showing decrypted message
def main():
    receiver = Receiver()
    sender = Sender()

    sender.generate_keys()
    receiver.generate_keys()

    sender.set_message("message.txt")
    sender.encrypt_message()
    sender.send_message()

    receiver.receive_message_data()
    receiver.decrypt_message()

    print("Decrypted message:", receiver.message)


if __name__ == "__main__":
    main()
