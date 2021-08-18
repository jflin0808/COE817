import socket                   # Import socket module
import random
import ast
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP



s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.


def generate_nonce(length=8):
    return ''.join([str(random.randint(0,9)) for i in range(length)])


def generate_key():
    key = get_random_bytes(8)
    return key


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


# Generate Public and Private Keys for Initiator A  
keys = RSA.generate(1024)
privKey = keys.exportKey('PEM')
pubKey = keys.publickey().exportKey('PEM')
rsa_pub_key_a = RSA.importKey(pubKey)
rsa_priv_key_a = RSA.importKey(privKey)

s.connect(('127.0.0.1', port))
# Send and receive public keys for client and server
s.send(pubKey)
responderB_pk = s.recv(1024)
rsa_pub_key_b = RSA.importKey(responderB_pk)
encryptor = PKCS1_OAEP.new(rsa_pub_key_b)
decryptor = PKCS1_OAEP.new(rsa_priv_key_a)

# Key Distribution Send Part 1:
N1 = generate_nonce()
message1 = N1 + 'INITIATOR A'
encrypted_message1 = encryptor.encrypt(message1.encode('utf-8'))
s.send(encrypted_message1)
print("Message1: {}".format(message1))
print("Encrypted message1: {}".format(encrypted_message1))

# Key Distribution Receive Part 2:
encrypted_message2 = s.recv(1024)
message2 = decryptor.decrypt(ast.literal_eval(str(encrypted_message2)))
nonce2 = message2[8:]
print("Received encrypted message2: {}".format(encrypted_message2))
print("Received message2: {}".format(message2))
print("Received nonce2: {}".format(nonce2))

# Key Distribution Send Part 3:
message3 = nonce2
encrypted_message3 = encryptor.encrypt(message3)
s.send(encrypted_message3)
print("Message3: {}".format(message3))
print("Encrypted message3: {}".format(encrypted_message3))

# Key Distribution Send Part 4:
session_key = generate_key()
new_encryptor = PKCS1_OAEP.new(rsa_priv_key_a)
message4 = new_encryptor.encrypt(session_key)
encrypted_message4 = encryptor.encrypt(new_encryptor.decrypt(message4))
s.send((encrypted_message4))
print("Session Key: {}".format(session_key))
print("Encrypted message4: {}".format(encrypted_message4))


# Messaging Application:
auth_message = s.recv(1024)
print(auth_message)
sending = True

# Send Image:
file = open('img.jpg', 'rb')
image_data = file.read()
s.send(image_data)

while sending:
    message = input("""Please enter a message to encrypt and send to the server(to exit enter 0): \n""")
    encrypted_message = encrypt(message.encode('utf-8'), session_key)
    print("Encrypted Message: {}".format(encrypted_message))
    s.send(encrypted_message)
    if message == '0':
        sending = False
    