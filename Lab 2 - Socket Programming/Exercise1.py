from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Exercise 1: Part A
message = input("Please enter a message to encrypt using DES: ")
key = b'01234567'
iv = get_random_bytes(8)
# Encode
e_cipher = DES.new(key, DES.MODE_OFB, iv)
encrypted_message = e_cipher.encrypt(message.encode())
print("The encrypted DES message is {}{}".format(iv, encrypted_message))
# Decode
d_cipher = DES.new(key, DES.MODE_OFB, iv)
decrypted_message = d_cipher.decrypt(encrypted_message)
print("The decrypted DES message is: ", decrypted_message.decode("utf-8"))


# Exercise 2: Part B
keys = RSA.generate(1024)
privKey = keys.export_key('PEM')
pubKey = keys.publickey().exportKey('PEM')
message = input("Please enter a message to encrypt using RSA: ")
message = str.encode(message)

rsa_pub_key = RSA.importKey(pubKey)
rsa_pub_key = PKCS1_OAEP.new(rsa_pub_key)
encrypted = rsa_pub_key.encrypt(message)
print("Encrypted RSA message: ", encrypted)

rsa_priv_key = RSA.importKey(privKey)
rsa_priv_key = PKCS1_OAEP.new(rsa_priv_key)
decrypted = rsa_priv_key.decrypt(encrypted)
print('Decrypted RSA message:', decrypted.decode("utf-8"))

