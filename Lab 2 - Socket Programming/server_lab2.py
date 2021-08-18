import socket                   # Import socket module
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))     # Bind to the port
s.listen(5)                     # Now wait for client connection.


def append_space_padding(plaintext, blocksize=8):
    while len(plaintext) % blocksize !=0:
        plaintext += '0'
    return plaintext


def remove_space_padding(plaintext, blocksize=8):
    return plaintext.replace("0", "")


def encrypt(Plaintext_pad, key):
    formatted_key = ""
    for char in key:
        if len(formatted_key) < 8:
            formatted_key += char

    iv = get_random_bytes(8)
    cipher = DES.new(formatted_key.encode(), DES.MODE_OFB, iv)
    encrypted_message = cipher.encrypt(Plaintext_pad.encode())
    return iv + encrypted_message


def decrypt(ciphertext, key):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_OFB, iv)
    decrypted_message = cipher.decrypt(ciphertext)
    return iv + decrypted_message


IDB = "RESPONDER B"
KM = "NETWORK SECURITY"
KS = "RYERSON"

while True:
    conn, addr = s.accept()     # Establish connection with client.
    print("Connection from {} has been established!".format(addr))
    conn.send(bytes("Welcome to the server!", "utf-8"))

    # Receive message 1
    m1_recv = conn.recv(11)
    IDA = m1_recv.decode("utf-8")
    print("The received message 1: ", IDA)

    # Pad message 2
    m2 = KS + IDA + IDB
    padded_m2 = append_space_padding(m2)
    print(padded_m2)
    # Encrypt and send message 2
    encrypted_padded_m2 = encrypt(padded_m2, KM)
    print("The ciphertext of message 2: ", encrypted_padded_m2)
    final_m2 = KM[0:8].encode() + encrypted_padded_m2
    conn.send(final_m2)

    # Receive message 3
    m3_recv = conn.recv(128)
    print("The received ciphertext of message 3: ", m3_recv)
    decrypted_m3 = decrypt(m3_recv, KS.encode() + '0'.encode())
    print("The decrypted message 3 is: ", decrypted_m3[8:])
    conn.close()


