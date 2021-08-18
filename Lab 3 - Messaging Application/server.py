import socket                   # Import socket module
import random
import ast
from PIL import Image
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))     # Bind to the port
s.listen(5)                     # Now wait for client connection.
running = True

def generate_nonce(length=8):
    return ''.join([str(random.randint(0,9)) for i in range(length)])


def encrypt(Plaintext_pad, key):
    iv = get_random_bytes(8)
    cipher = DES.new(formatted_key.encode(), DES.MODE_OFB, iv)
    encrypted_message = cipher.encrypt(Plaintext_pad.encode())
    return iv + encrypted_message


def decrypt(ciphertext, key):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_OFB, iv)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message


# Generate Public and Private Keys for Responder B  
keys = RSA.generate(1024)
privKey = keys.exportKey('PEM')
pubKey = keys.publickey().exportKey('PEM')
rsa_pub_key_b = RSA.importKey(pubKey)
rsa_priv_key_b = RSA.importKey(privKey)

while running:
    conn, addr = s.accept()     # Establish connection with client.

    # Send and receive public keys of server and client
    conn.send(pubKey)
    initiatorA_pk = conn.recv(1024)
    rsa_pub_key_a = RSA.importKey(initiatorA_pk)
    encryptor = PKCS1_OAEP.new(rsa_pub_key_a)
    decryptor = PKCS1_OAEP.new(rsa_priv_key_b)

    # Key Distribution Receive Part 1:
    encrypted_message1 = conn.recv(1024)
    message1 = decryptor.decrypt(ast.literal_eval(str(encrypted_message1)))
    nonce1 = message1.decode('utf-8')[:8]
    print("Received encrypted message1: {}".format(encrypted_message1))
    print("Received message1: {}".format(message1))
    print("Received nonce1: {}".format(nonce1))

    # Key Distribution Send Part 2:
    nonce2 = generate_nonce()
    message2 = nonce1 + nonce2
    encrypted_message2 = encryptor.encrypt(message2.encode('utf-8'))
    conn.send(encrypted_message2)
    print("Message 2: {}".format(message2))
    print("Encrypted message2: {}".format(encrypted_message2) )

    # Key Distribution Receive Part 3:
    encrypted_message3 = conn.recv(1024)
    message3 = decryptor.decrypt(ast.literal_eval(str(encrypted_message3)))
    print("Received encrypted message3: {}".format(encrypted_message3))
    print("Received message3: {}".format(message3))
    print("Received nonce2: {}".format(nonce2))

    # Key Distribution Receive Part 4:
    new_decryptor = PKCS1_OAEP.new(rsa_priv_key_b)
    encrypted_message4 = conn.recv(1024)
    message4 = decryptor.decrypt(ast.literal_eval(str(encrypted_message4)))
    session_key = new_decryptor.decrypt(new_decryptor.encrypt(message4))
    print("Received encrypted message4: {}".format(encrypted_message4))
    print("Received session key: {}\n".format(session_key))



    # Messaging Application:
    receiving = True
    conn.send(bytes("Secure Communication Channel Authenticated.", "utf-8"))

    # Receive Image:
    file = open('server_img.jpg', "wb")
    image_chunk = conn.recv(170000)
    file.write(image_chunk)
    img = Image.open('server_img.jpg')
    img.show()

    print("Messaging Application:")
    while receiving:
        encrypted_message = conn.recv(1024)
        print("Received encrypted message: {}".format(encrypted_message))
        message = decrypt(encrypted_message, session_key)
        print("Client sent: {}".format(message))

        if message == '0':
            receiving = False
            running = False