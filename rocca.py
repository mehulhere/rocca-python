from dataclasses import dataclass

@dataclass
class RoccaCipher:
    VERBOSE: bool = False  # Set to True to enable internal layer messages

    # AES S-Box: A substitution box used in AES encryption for byte substitution
    S_BOX = [
        # 0     1    2    3     4    5    6    7     8    9    A    B     C    D    E    F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  # 0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  # 1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  # 2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  # 3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  # 4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  # 5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  # 6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  # 7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  # 8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  # 9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  # A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  # B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  # C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  # D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  # E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   # F
    ]

    # Constants Z0 and Z1 used in the cipher's initialization and rounds
    Z0 = bytes.fromhex('428a2f98d728ae227137449123ef65cd')
    Z1 = bytes.fromhex('b5c0fbcfec4d3b2fe9b5dba58189dbbc')

    def sub_bytes(self, state: bytes) -> bytes:
        """
        Apply the AES S-Box substitution to each byte in the state.
        :param state: Current state as bytes.
        :return: Substituted state as bytes.
        """
        return bytes([self.S_BOX[b] for b in state])  # Substitute each byte using S_BOX

    def shift_rows(self, state: bytes) -> bytes:
        """
        Perform the ShiftRows operation on the state.
        :param state: Current state as bytes.
        :return: State after ShiftRows as bytes.
        """
        s = list(state)  # Convert state to a mutable list
        # Row 0: No shift
        # Row 1: Shift left by 1
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        # Row 2: Shift left by 2
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        # Row 3: Shift left by 3 (or right by 1)
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        return bytes(s)  # Convert back to bytes

    def xtime(self, a: int) -> int:
        """
        Multiply by x in GF(2^8), used in MixColumns.
        :param a: Byte value.
        :return: Result after multiplication.
        """
        # If the highest bit is set, perform modulo with 0x1B
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

    def mix_single_column(self, a: bytearray):
        """
        Perform MixColumns operation on a single column.
        :param a: Column as a bytearray.
        """
        t = a[0] ^ a[1] ^ a[2] ^ a[3]  # Compute the temporary variable t
        u = a[0]  # Store the first byte
        # Perform MixColumns transformation on each byte
        a[0] ^= t ^ self.xtime(a[0] ^ a[1])
        a[1] ^= t ^ self.xtime(a[1] ^ a[2])
        a[2] ^= t ^ self.xtime(a[2] ^ a[3])
        a[3] ^= t ^ self.xtime(a[3] ^ u)

    def mix_columns(self, state: bytes) -> bytes:
        """
        Perform the MixColumns operation on the entire state.
        :param state: Current state as bytes.
        :return: State after MixColumns as bytes.
        """
        s = list(state)  # Convert state to a mutable list
        for i in range(4):  # Iterate over each of the 4 columns
            col = bytearray(s[i*4:(i+1)*4])  # Extract the current column
            self.mix_single_column(col)  # Mix the column
            s[i*4:(i+1)*4] = col  # Replace the column in the state
        return bytes(s)  # Convert back to bytes

    def A(self, state: bytes) -> bytes:
        """
        Perform the AES round transformations: SubBytes, ShiftRows, MixColumns.
        :param state: Current state as bytes.
        :return: Transformed state as bytes.
        """
        state = self.sub_bytes(state)  # Apply SubBytes
        state = self.shift_rows(state)  # Apply ShiftRows
        state = self.mix_columns(state)  # Apply MixColumns
        return state  # Return the transformed state

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """
        XOR two byte sequences.
        :param a: First byte sequence.
        :param b: Second byte sequence.
        :return: Resulting byte sequence after XOR.
        """
        return bytes([x ^ y for x, y in zip(a, b)])  # Perform byte-wise XOR

    def aes_round(self, X: bytes, Y: bytes) -> bytes:
        """
        Perform an AES round with inputs X and Y.
        :param X: First input as bytes.
        :param Y: Second input as bytes.
        :return: Output after AES round as bytes.
        """
        X = self.reverse_bytes(X)  # Reverse the bytes of X
        Y = self.reverse_bytes(Y)  # Reverse the bytes of Y
        X = self.A(X)  # Apply AES transformations to X
        return self.reverse_bytes(self.xor_bytes(X, Y))  # XOR with Y and reverse bytes

    def reverse_bytes(self, state: bytes) -> bytes:
        """
        Reverse the order of bytes in the state.
        :param state: Byte sequence to reverse.
        :return: Reversed byte sequence.
        """
        return state[::-1]  # Slice to reverse

    def R(self, S: list, X0: bytes, X1: bytes) -> list:
        """
        Perform a transformation round on the state S using inputs X0 and X1.
        :param S: Current state as a list of byte sequences.
        :param X0: First input as bytes.
        :param X1: Second input as bytes.
        :return: Updated state after the round.
        """
        tmp7 = S[7]  # Temporary storage for block 7
        tmp6 = S[6]  # Temporary storage for block 6
        S_new = [None] * 8  # Initialize new state list
        S_new[7] = self.xor_bytes(S[6], S[0])  # Update block 7
        S_new[6] = self.aes_round(S[5], S[4])  # Update block 6 using AES round
        S_new[5] = self.aes_round(S[4], S[3])  # Update block 5 using AES round
        S_new[4] = self.xor_bytes(S[3], X1)    # Update block 4 by XORing block 3 and X1
        S_new[3] = self.aes_round(S[2], S[1])  # Update block 3 using AES round
        S_new[2] = self.xor_bytes(S[1], tmp6)  # Update block 2 by XORing block 1 and tmp6
        S_new[1] = self.aes_round(S[0], tmp7)  # Update block 1 using AES round
        S_new[0] = self.xor_bytes(tmp7, X0)    # Update block 0 by XORing tmp7 and X0
        return S_new  # Return the updated state

    def pad(self, data: bytes, block_size: int) -> bytes:
        """
        Pad the data with zero bytes to make its length a multiple of block_size.
        :param data: Data to pad.
        :param block_size: Block size in bytes.
        :return: Padded data.
        """
        padding_length = (block_size - len(data) % block_size) % block_size  # Calculate padding needed
        return data + bytes([0] * padding_length)  # Append padding

    def pad_left(self, data: bytes, block_size: int) -> bytes:
        """
        Pad the data on the left with zero bytes to make its length a multiple of block_size.
        :param data: Data to pad.
        :param block_size: Block size in bytes.
        :return: Left-padded data.
        """
        padding_length = (block_size - len(data) % block_size) % block_size  # Calculate padding needed
        return bytes([0] * padding_length) + data  # Prepend padding

    def split_blocks(self, data: bytes, block_size: int) -> list:
        """
        Split the data into blocks of block_size bytes.
        :param data: Data to split.
        :param block_size: Size of each block in bytes.
        :return: List of data blocks.
        """
        return [data[i:i + block_size] for i in range(0, len(data), block_size)]  # List comprehension to split

    def to_bytes_length(self, length: int) -> bytes:
        """
        Convert an integer length to a 16-byte big-endian representation.
        :param length: Length as integer.
        :return: Length as 16-byte big-endian bytes.
        """
        return length.to_bytes(16, 'big')  # Convert integer to bytes

    def initialize_state(self, N: bytes, K0: bytes, K1: bytes) -> list:
        """
        Initialize the state S with the nonce and keys.
        :param N: Nonce as bytes.
        :param K0: First key part as bytes.
        :param K1: Second key part as bytes.
        :return: Initialized state as a list of byte sequences.
        """
        S = [None] * 8  # Initialize state list with 8 blocks
        S[0] = K1  # Set block 0 to K1
        S[1] = N   # Set block 1 to nonce
        S[2] = self.Z0  # Set block 2 to constant Z0
        S[3] = self.Z1  # Set block 3 to constant Z1
        S[4] = self.xor_bytes(N, K1)  # Set block 4 to N XOR K1
        S[5] = self.zeros(16)  # Set block 5 to all zeros
        S[6] = K0  # Set block 6 to K0
        S[7] = self.zeros(16)  # Set block 7 to all zeros

        if self.VERBOSE:
            print("Initial State: ")
            for idx, block in enumerate(S):
                print(f"Block {idx}: {self.bytes_to_hexstr(block)}")  # Print each block in hex

        # Perform 20 initialization rounds
        for i in range(20):
            S = self.R(S, self.Z0, self.Z1)  # Update state using round function R with Z0 and Z1
            if self.VERBOSE:
                print(f"Initialization Round: {i + 1}")
                for idx, block in enumerate(S):
                    print(f"Block {idx}: {self.bytes_to_hexstr(block)}")  # Print state after each round
                print()
        return S  # Return the initialized state

    def process_ad(self, S: list, AD: bytes) -> list:
        """
        Process the associated data (AD) through the cipher.
        :param S: Current state as a list of byte sequences.
        :param AD: Associated data as bytes.
        :return: Updated state after processing AD.
        """
        if len(AD) == 0:
            return S  # If AD is empty, return current state

        AD = self.pad_left(AD, 32)  # Pad AD on the left to a multiple of 32 bytes
        blocks = self.split_blocks(AD, 32)  # Split AD into 32-byte blocks

        for block in blocks:
            AD0 = block[:16]  # First 16 bytes of the block
            AD1 = block[16:]  # Last 16 bytes of the block

            if self.VERBOSE:
                print(f"Processing AD0: {self.bytes_to_hexstr(AD0)}")
                print(f"Processing AD1: {self.bytes_to_hexstr(AD1)}")

            S = self.R(S, AD1, AD0)  # Update state using round function R with AD1 and AD0

            if self.VERBOSE:
                print("Processing Rounds:")
                for idx, block in enumerate(S):
                    print(f"Block {idx}: {self.bytes_to_hexstr(block)}")  # Print state after processing
                print()
        return S  # Return updated state after processing all AD blocks

    def encrypt(self, S: list, M: bytes) -> tuple:
        """
        Encrypt the plaintext message M using the current state S.
        :param S: Current state as a list of byte sequences.
        :param M: Plaintext message as bytes.
        :return: Tuple containing updated state and ciphertext.
        """
        if len(M) == 0:
            return S, b''  # If plaintext is empty, return current state and empty ciphertext

        M = self.pad_left(M, 32)  # Pad plaintext on the left to a multiple of 32 bytes
        blocks = self.split_blocks(M, 32)  # Split plaintext into 32-byte blocks
        C = b''  # Initialize ciphertext as empty bytes

        for block in blocks:
            M0 = block[:16]  # First 16 bytes of the block
            M0 = self.reverse_bytes(M0)  # Reverse bytes of M0
            M1 = block[16:]  # Last 16 bytes of the block
            M1 = self.reverse_bytes(M1)  # Reverse bytes of M1

            if self.VERBOSE:
                print(f"Encrypting M0: {self.bytes_to_hexstr(M0)}")
                print(f"Encrypting M1: {self.bytes_to_hexstr(M1)}")

            # Compute ciphertext blocks C0 and C1 using AES rounds and XOR operations
            C0 = self.xor_bytes(self.aes_round(S[1], S[5]), M0)
            C1 = self.xor_bytes(self.aes_round(self.xor_bytes(S[0], S[4]), S[2]), M1)
            C += C0 + C1  # Append ciphertext blocks to C

            S = self.R(S, M0, M1)  # Update state using round function R with M0 and M1

            if self.VERBOSE:
                print("Encryption Rounds:")
                for idx, block in enumerate(S):
                    print(f"Block {idx}: {self.bytes_to_hexstr(block)}")  # Print state after encryption round
                print()

        C = C[:len(M)]  # Truncate ciphertext to original plaintext length
        C = bytearray(C)  # Convert ciphertext to mutable bytearray for byte-wise operations

        # Reverse each 16-byte block in the ciphertext
        for i in range(0, len(C), 16):
            C[i: i + 16] = self.reverse_bytes(C[i: i + 16])

        C = bytes(C)  # Convert back to immutable bytes
        return S, C  # Return updated state and ciphertext

    def finalize(self, S: list, AD_length_bits: int, M_length_bits: int) -> bytes:
        """
        Finalize the encryption by processing the lengths of AD and M, and generating the authentication tag.
        :param S: Current state as a list of byte sequences.
        :param AD_length_bits: Length of associated data in bits.
        :param M_length_bits: Length of message in bits.
        :return: Authentication tag as bytes.
        """
        length_AD = self.to_bytes_length(AD_length_bits)  # Convert AD length to 16-byte representation
        length_M = self.to_bytes_length(M_length_bits)    # Convert M length to 16-byte representation

        # Perform 20 finalization rounds with length information
        for i in range(20):
            S = self.R(S, length_AD, length_M)  # Update state using round function R with lengths
            if self.VERBOSE:
                print(f"After finalization round {i + 1}:")
                for idx, block in enumerate(S):
                    print(f"Block {idx}: {self.bytes_to_hexstr(block)}")  # Print state after each finalization round
                print()

        T = S[0]  # Initialize tag with block 0

        # XOR all blocks to generate the final tag
        for i in range(1, 8):
            T = self.xor_bytes(T, S[i])
            if self.VERBOSE:
                print(f"Tag Generation round {i}:")
                print(f"T after round {i}: {self.bytes_to_hexstr(self.reverse_bytes(T))}")  # Print intermediate tag
                print()

        T = self.reverse_bytes(T)  # Reverse bytes of the final tag
        return T  # Return the authentication tag

    def roc_encrypt(self, K0: bytes, K1: bytes, N: bytes, AD: bytes, M: bytes) -> tuple:
        """
        Perform the complete Rocca encryption process.
        :param K0: First key part as bytes.
        :param K1: Second key part as bytes.
        :param N: Nonce as bytes.
        :param AD: Associated data as bytes.
        :param M: Plaintext message as bytes.
        :return: Tuple containing ciphertext and authentication tag.
        """
        S = self.initialize_state(N, K0, K1)  # Initialize the state with nonce and keys
        S = self.process_ad(S, AD)            # Process the associated data
        S, C = self.encrypt(S, M)             # Encrypt the plaintext message
        T = self.finalize(S, len(AD) * 8, len(M) * 8)  # Finalize and generate the tag
        return C, T  # Return ciphertext and tag

    def roc_decrypt(self, K0: bytes, K1: bytes, N: bytes, AD: bytes, C: bytes, T: bytes) -> bytes:
        """
        Perform the Rocca decryption process.
        :param K0: First key part as bytes.
        :param K1: Second key part as bytes.
        :param N: Nonce as bytes.
        :param AD: Associated data as bytes.
        :param C: Ciphertext as bytes.
        :param T: Authentication tag as bytes.
        :return: Decrypted plaintext message as bytes if authentication succeeds; otherwise, None.
        """
        S = self.initialize_state(N, K0, K1)  # Initialize the state with nonce and keys
        S = self.process_ad(S, AD)            # Process the associated data
        S, M = self.encrypt(S, C)             # Decrypt the ciphertext (encryption used for decryption)
        T_computed = self.finalize(S, len(AD) * 8, len(C) * 8)  # Compute the authentication tag

        if T_computed == T:  # Verify if the computed tag matches the provided tag
            return M  # Authentication successful; return plaintext
        else:
            if self.VERBOSE:
                print("Authentication failed: Computed tag does not match the provided tag.")  # Error message
            return None  # Authentication failed

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """
        XOR two byte sequences.
        :param a: First byte sequence.
        :param b: Second byte sequence.
        :return: Resulting byte sequence after XOR.
        """
        return bytes([x ^ y for x, y in zip(a, b)])  # Perform byte-wise XOR

    def zeros(self, n: int) -> bytes:
        """
        Generate a byte sequence of n zero bytes.
        :param n: Number of zero bytes.
        :return: Byte sequence of zeros.
        """
        return bytes([0] * n)  # Create n zero bytes

    @staticmethod
    def hexstr_to_bytes(s: str) -> bytes:
        """
        Convert a hex string to bytes, removing spaces and newlines.
        :param s: Hexadecimal string.
        :return: Corresponding byte sequence.
        """
        s = s.replace(' ', '').replace('\n', '')  # Remove spaces and newlines
        return bytes.fromhex(s)  # Convert hex string to bytes

    @staticmethod
    def bytes_to_hexstr(b: bytes) -> str:
        """
        Convert bytes to a space-separated hex string.
        :param b: Byte sequence.
        :return: Hexadecimal string representation.
        """
        return ' '.join(['{:02x}'.format(x) for x in b])  # Format each byte as hex and join with spaces

    def verify_test_vector(self, test_vector_num: int, key_hex: str, nonce_hex: str, ad_hex: str,
                           plaintext_hex: str, expected_ciphertext_hex: str, expected_tag_hex: str):
        """
        Verify the cipher against a provided test vector.
        :param test_vector_num: Identifier for the test vector.
        :param key_hex: Key in hexadecimal string format.
        :param nonce_hex: Nonce in hexadecimal string format.
        :param ad_hex: Associated data in hexadecimal string format.
        :param plaintext_hex: Plaintext message in hexadecimal string format.
        :param expected_ciphertext_hex: Expected ciphertext in hexadecimal string format.
        :param expected_tag_hex: Expected authentication tag in hexadecimal string format.
        """
        K = self.hexstr_to_bytes(key_hex)  # Convert key hex string to bytes
        K0 = K[:16]  # Extract first 16 bytes as K0
        K1 = K[16:]  # Extract next 16 bytes as K1

        N = self.hexstr_to_bytes(nonce_hex)  # Convert nonce hex string to bytes
        AD = self.hexstr_to_bytes(ad_hex)     # Convert AD hex string to bytes
        M = self.hexstr_to_bytes(plaintext_hex)  # Convert plaintext hex string to bytes
        expected_C = self.hexstr_to_bytes(expected_ciphertext_hex)  # Convert expected ciphertext to bytes
        expected_T = self.hexstr_to_bytes(expected_tag_hex)  # Convert expected tag to bytes

        # Reverse the bytes as per original implementation
        C, T = self.roc_encrypt(self.reverse_bytes(K0), self.reverse_bytes(K1), 
                                self.reverse_bytes(N), self.reverse_bytes(AD), M)

        print(f'Test Vector #{test_vector_num}')  # Print test vector number
        print('Computed Ciphertext:')
        print(self.bytes_to_hexstr(C))  # Display computed ciphertext
        print('Expected Ciphertext:')
        print(self.bytes_to_hexstr(expected_C))  # Display expected ciphertext
        print('Ciphertext Match:', C == expected_C)  # Indicate if ciphertext matches
        print('Computed Tag:')
        print(self.bytes_to_hexstr(T))  # Display computed tag
        print('Expected Tag:')
        print(self.bytes_to_hexstr(expected_T))  # Display expected tag
        print('Tag Match:', T == expected_T)  # Indicate if tag matches
        print('--------------------------------------\n')  # Separator for readability
