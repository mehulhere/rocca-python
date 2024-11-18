from rocca import RoccaCipher  # Import the RoccaCipher class from the rocca module

# Test Vector #1
key_hex_1 = '''
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''  # Define the encryption key in hexadecimal format (32 bytes)

nonce_hex_1 = '''
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''  # Define the nonce (number used once) in hexadecimal format (16 bytes)

ad_hex_1 = '''
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''  # Define the associated data (AD) in hexadecimal format (32 bytes)

plaintext_hex_1 = '''
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''  # Define the plaintext message in hexadecimal format (64 bytes)

ciphertext_hex_1 = '''
15 89 2f 85 55 ad 2d b4 74 9b 90 92 65 71 c4 b8
c2 8b 43 4f 27 77 93 c5 38 33 cb 6e 41 a8 55 29
17 84 a2 c7 fe 37 4b 34 d8 75 fd cb e8 4f 5b 88
bf 3f 38 6f 22 18 f0 46 a8 43 18 56 50 26 d7 55
'''  # Define the expected ciphertext in hexadecimal format (64 bytes)

tag_hex_1 = '''
cc 72 8c 8b ae dd 36 f1 4c f8 93 8e 9e 07 19 bf
'''  # Define the expected authentication tag in hexadecimal format (16 bytes)


# Test Vector #2
key_hex_2 = '''
01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
'''  # Define the encryption key in hexadecimal format (32 bytes)

nonce_hex_2 = '''
01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
'''  # Define the nonce in hexadecimal format (16 bytes)

ad_hex_2 = '''
01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
'''  # Define the associated data in hexadecimal format (32 bytes)

plaintext_hex_2 = '''
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''  # Define the plaintext message in hexadecimal format (64 bytes)

ciphertext_hex_2 = '''
f9 31 a8 73 0b 2e 8a 3a f3 41 c8 3a 29 c3 05 25 32 5c 17 03 26 c2 9d 91 b2 4d 71 4f ec f3 85 fd 88 e6 50 ef 2e 2c 02 b3 7b 19 e7 0b b9 3f f8 2a a9 6d 50 c9 fd f0 53 43 f6 e3 6b 66 ee 7b da 69
'''  # Define the expected ciphertext in hexadecimal format (64 bytes)

tag_hex_2 = '''
ba d0 a5 36 16 59 9b fd b5 53 78 8f da ab ad 78
'''  # Define the expected authentication tag in hexadecimal format (16 bytes)


# Test Vector #3
key_hex_3 = '''
01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
'''  # Define the encryption key in hexadecimal format (32 bytes)

nonce_hex_3 = '''
01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
'''  # Define the nonce in hexadecimal format (16 bytes)

ad_hex_3 = '''
01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
'''  # Define the associated data in hexadecimal format (32 bytes)

plaintext_hex_3 = '''
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'''  # Define the plaintext message in hexadecimal format (64 bytes)

ciphertext_hex_3 = '''
26 5b 7e 31 41 41 fd 14 82 35 a5 30 5b 21 7a b2
91 a2 a7 ae ff 91 ef d3 ac 60 3b 28 e0 57 61 09
72 34 22 ef 3f 55 3b 0b 07 ce 72 63 f6 35 02 a0
05 91 de 64 8f 3e e3 b0 54 41 d8 31 3b 13 8b 5a
'''  # Define the expected ciphertext in hexadecimal format (64 bytes)

tag_hex_3 = '''
66 72 53 4a 8b 57 c2 87 bc f5 68 23 cd 1c db 5a
'''  # Define the expected authentication tag in hexadecimal format (16 bytes)


# Test Vector #4
key_hex_4 = '''
11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22
'''  # Define the encryption key in hexadecimal format (32 bytes)

nonce_hex_4 = '''
44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44
'''  # Define the nonce in hexadecimal format (16 bytes)

ad_hex_4 = '''
80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91
'''  # Define the associated data in hexadecimal format (18 bytes)

plaintext_hex_4 = '''
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
'''  # Define the plaintext message in hexadecimal format (64 bytes)

ciphertext_hex_4 = '''
34 8b 6f 6e fa d8 07 d2 46 eb f3 45 e7 30 d8 3e 
59 63 bd 6d 29 ee dc 49 a1 35 40 54 5a e2 32 a7 
03 4e d4 ef 19 8a 1e b1 f8 b1 16 a1 76 03 54 b7 
72 60 d6 f2 cc a4 6e fc ad fc 47 65 ff fe 9f 09
'''  # Define the expected ciphertext in hexadecimal format (64 bytes)

tag_hex_4 = '''
a9 f2 06 94 56 55 9d e3 e6 9d 23 3e 15 4b a0 5e
'''  # Define the expected authentication tag in hexadecimal format (16 bytes)


# Verify Test Vectors
cipher = RoccaCipher(VERBOSE=False)  # Instantiate RoccaCipher with verbose mode disabled

# Verify Test Vector #1
cipher.verify_test_vector(
    1,  # Test vector number
    key_hex_1,  # Encryption key in hexadecimal
    nonce_hex_1,  # Nonce in hexadecimal
    ad_hex_1,  # Associated data in hexadecimal
    plaintext_hex_1,  # Plaintext message in hexadecimal
    ciphertext_hex_1,  # Expected ciphertext in hexadecimal
    tag_hex_1  # Expected authentication tag in hexadecimal
)  # Call the verification method for Test Vector #1

# Verify Test Vector #2
cipher.verify_test_vector(
    2,  # Test vector number
    key_hex_2,  # Encryption key in hexadecimal
    nonce_hex_2,  # Nonce in hexadecimal
    ad_hex_2,  # Associated data in hexadecimal
    plaintext_hex_2,  # Plaintext message in hexadecimal
    ciphertext_hex_2,  # Expected ciphertext in hexadecimal
    tag_hex_2  # Expected authentication tag in hexadecimal
)  # Call the verification method for Test Vector #2

# Verify Test Vector #3
cipher.verify_test_vector(
    3,  # Test vector number
    key_hex_3,  # Encryption key in hexadecimal
    nonce_hex_3,  # Nonce in hexadecimal
    ad_hex_3,  # Associated data in hexadecimal
    plaintext_hex_3,  # Plaintext message in hexadecimal
    ciphertext_hex_3,  # Expected ciphertext in hexadecimal
    tag_hex_3  # Expected authentication tag in hexadecimal
)  # Call the verification method for Test Vector #3

# Verify Test Vector #4
cipher.verify_test_vector(
    4,  # Test vector number
    key_hex_4,  # Encryption key in hexadecimal
    nonce_hex_4,  # Nonce in hexadecimal
    ad_hex_4,  # Associated data in hexadecimal
    plaintext_hex_4,  # Plaintext message in hexadecimal
    ciphertext_hex_4,  # Expected ciphertext in hexadecimal
    tag_hex_4  # Expected authentication tag in hexadecimal
)  # Call the verification method for Test Vector #4
