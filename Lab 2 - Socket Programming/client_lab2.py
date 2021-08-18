import socket                   # Import socket module
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def append_space_padding(plaintext, blocksize=8):
    while len(plaintext) % blocksize !=0:
        plaintext += '0'
    return plaintext


def remove_space_padding(plaintext, blocksize=8):
    return plaintext.replace("0", "")


def encrypt(Plaintext_pad, key):
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_OFB, iv)
    encrypted_message = cipher.encrypt(Plaintext_pad)
    return iv + encrypted_message


def decrypt(ciphertext, key):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_OFB, iv)
    decrypted_message = cipher.decrypt(ciphertext)
    return iv + decrypted_message


s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.

s.connect(('127.0.0.1', port))
# Welcome Message
message = s.recv(1024)
print(message.decode("utf-8"))

# Send message 1
IDA = "INITIATOR A"
s.send(bytes(IDA,"utf-8"))
print("Cleartext of message 1: {}".format(IDA))

# Receive message 2
m2_recv = s.recv(128)
print("The receieved ciphertext of message 2: ", m2_recv)
ciphertext = m2_recv[8:]
KM = m2_recv[:8]
# Decrypt message 2
decrypted_m2 = decrypt(ciphertext, KM)
print("The decrypted ciphertext of message 2: ", decrypted_m2[8:37])

# Extract Information from message 2
KS = decrypted_m2[8:15]
IDB = decrypted_m2[26:37]
encrypted_m3 = encrypt(IDB, KS + '0'.encode())
s.send(encrypted_m3)
s.close()
