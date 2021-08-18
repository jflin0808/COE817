alphabet = 'abcdefghijklmnopqrstuvwxyz'

def caesar_encrypt(plain_text, key):
    cipher_text = ''
    formatted_plain_text = plain_text.lower()
    for i in range(len(formatted_plain_text)):
        if formatted_plain_text[i] == ' ':
            cipher_text += ' '
        for j in range(len(alphabet)):
            if formatted_plain_text[i] == alphabet[j]:
                cipher_text += alphabet[(j+key)%26]
    return cipher_text.upper()

def caesar_decrypt(cipher_text, key):
    plain_text = ''
    formatted_cipher_text = cipher_text.lower()
    for i in range(len(formatted_cipher_text)):
        if formatted_cipher_text[i] == '.':
            plain_text += '.'
        if formatted_cipher_text[i] == ' ':
            plain_text += ' '
        if formatted_cipher_text[i] == ',':
            plain_text += ','    
        for j in range(len(alphabet)):
            if formatted_cipher_text[i] == alphabet[j]:
                plain_text += alphabet[(j-key)%26]
    return plain_text

def vigenere_encrypt(plain_text, key):
    cipher_text = ''
    formatted_key = ''
    # Removes all spaces and makes text lower case
    formatted_plain_text = plain_text.lower().replace(' ', '')
    
    # Making any given key the same length as the plain text
    while(len(formatted_key) < len(formatted_plain_text)):
        for i in range(len(key)):
            if (len(formatted_key) == len(formatted_plain_text)):
                break
            formatted_key += key[i]

    # String concatenates vigenere encrypted characters to ciper_text
    for i in range(len(formatted_plain_text)):
        # Vigenere Algorithm to determine which letter from the alphabet will be used: C = (plain_text[i] + key[i]) % 26
        cipher_text += alphabet[(alphabet.find(formatted_plain_text[i]) + alphabet.find(formatted_key[i])) % 26]
    # Returns cipher in capitalized format
    return cipher_text.upper()


def vigenere_decrypt(cipher_text, key):
    plain_text = ''
    formatted_key = ''
    # Removes all spaces and makes text lower case
    formatted_cipher_text = cipher_text.lower().replace(' ', '')
    
    # Making any given key the same length as the cipher text
    while(len(formatted_key) < len(formatted_cipher_text)):
        for i in range(len(key)):
            if (len(formatted_key) == len(formatted_cipher_text)):
                break
            formatted_key += key[i]

    # String concatenates vigenere decrypted characters to plain_text
    for i in range(len(formatted_cipher_text)):
        # Vigenere Algorithm to determine which letter from the alphabet will be used: p = (cipher_text[i] - key[i]) % 26
        plain_text += alphabet[(alphabet.find(formatted_cipher_text[i]) - alphabet.find(formatted_key[i])) % 26]
    return plain_text


if __name__ == "__main__":
    # Exercise 1: Part A
    print("\nExercise 1: Part A")
    encrypted_a = caesar_encrypt("The downfall of Icarus was caused by his Hubris", 5)
    decrypted_a = caesar_decrypt(encrypted_a, 5)
    print("Initial text: The downfall of Icarus was caused by his Hubris")
    print("Encrypted text using Caesar algorithm with a key of 5: {}".format(encrypted_a))
    print("Decrypted text using Caesar algorithm: {}".format(decrypted_a))

    # Exercise 1: Part B
    print("\nExercise 1: Part B")
    given_text = "Glzkx g cnork, Rozzrk Jaiqrotm cgy zoxkj ul vrgeotm. Ynk yixgshrkj av utzu znk mxgyye hgtq gtj lrallkj uaz nkx lkgznkxy zu jxe. Gxuatj nkx znk cotj cnoyvkxkj ot znk mxgyy. Znk rkgbky xayzrkj gtj ubkxnkgj znk yqe mxkc jgxq. Rozzrk Jaiqrotm xkgrofkj ynk cgy grr grutk."
    print("Given Text: {}".format(given_text))
    decrypted_b = caesar_decrypt(given_text, 6)
    print("Decrypted text using a key of 6: {}".format(decrypted_b))
    print("Question: Explain how you break the Ciphertext, provide details")
    print("\nTo break the caesar cipher, it requires systematic trial and error.\nThe method is to use different key values until the sentence is legible\n")

    # Exercise 2: 
    message = input("Please enter a message to be encrypted: ")
    key = input("Please enter a key to use for encryption: ")
    encrypted_v = vigenere_encrypt(message, key)
    decrypted_v = vigenere_decrypt(encrypted_v, key)
    print("Here is your encrypted text: {}".format(encrypted_v))
    print("Here is your decrypted text: {}".format(decrypted_v))
