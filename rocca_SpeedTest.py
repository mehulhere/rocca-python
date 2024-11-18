import time  # Import time module for measuring execution time
import os    # Import os module for generating random bytes
from rocca import RoccaCipher  # Import the RoccaCipher class from the rocca module
import statistics  # Import statistics module for statistical analysis

def generate_random_bytes(size_in_bytes):
    """
    Generate a sequence of random bytes.
    :param size_in_bytes: Number of random bytes to generate.
    :return: Random bytes of specified size.
    """
    return os.urandom(size_in_bytes)  # Use os.urandom for cryptographically secure random bytes

def format_time(elapsed_time):
    """
    Format the elapsed time from seconds to milliseconds with three decimal places.
    :param elapsed_time: Time elapsed in seconds.
    :return: Formatted time string in milliseconds.
    """
    return f"{elapsed_time * 1000:.3f} ms"  # Convert seconds to milliseconds and format

def main():
    """
    Main function to perform speed tests on RoccaCipher with different plaintext sizes.
    It measures the encryption time over multiple iterations and computes statistical metrics.
    """
    cipher = RoccaCipher()  # Instantiate the RoccaCipher object

    # Define the encryption key as a hexadecimal string (32 bytes for K0 and K1)
    key_hex = '000102030405060708090a0b0c0d0e0f' * 2
    # Define the nonce as a hexadecimal string (16 bytes)
    nonce_hex = '101112131415161718191a1b1c1d1e1f'
    ad_hex = ''  # Associated Data (AD) is empty in this test

    # Convert hexadecimal strings to bytes using the utility method from RoccaCipher
    key_bytes = RoccaCipher.hexstr_to_bytes(key_hex)
    K0 = key_bytes[:16]  # Split the key into K0 (first 16 bytes)
    K1 = key_bytes[16:]  # and K1 (next 16 bytes)
    N = RoccaCipher.hexstr_to_bytes(nonce_hex)  # Convert nonce to bytes
    AD = RoccaCipher.hexstr_to_bytes(ad_hex)     # Convert AD to bytes

    # Define plaintext sizes in bits and their corresponding byte sizes
    plaintext_sizes = {
        '256 bits': 32,    # 256 bits = 32 bytes
        '1024 bits': 128,  # 1024 bits = 128 bytes
        '8192 bits': 1024  # 8192 bits = 1024 bytes
    }

    iterations = 1000  # Number of encryption iterations per test
    # Initialize a dictionary to store run times for each plaintext size
    run_times = {size: [] for size in plaintext_sizes.keys()}

    # Print the header for the speed test output
    print("RoccaCipher Speed Test with Statistical Analysis")
    print("==============================================\n")
    print(f"Number of Iterations per Test: {iterations}\n")
    print(f"Keys and Nonce are fixed for all tests.\n")

    # Iterate over each plaintext size and perform encryption tests
    for size_label, size_bytes in plaintext_sizes.items():
        plaintext = generate_random_bytes(size_bytes)  # Generate random plaintext of specified size
        _, _ = cipher.roc_encrypt(K0, K1, N, AD, plaintext)  # Warm-up encryption to initialize any caches

        # Perform encryption for the specified number of iterations
        for _ in range(iterations):
            start_time = time.perf_counter()  # Record the start time
            _, _ = cipher.roc_encrypt(K0, K1, N, AD, plaintext)  # Encrypt the plaintext
            end_time = time.perf_counter()  # Record the end time
            elapsed_time = end_time - start_time  # Calculate elapsed time
            run_times[size_label].append(elapsed_time)  # Store the elapsed time

        # Calculate statistical metrics for the collected run times
        avg_time = statistics.mean(run_times[size_label])  # Average encryption time
        min_time = min(run_times[size_label])  # Minimum encryption time
        max_time = max(run_times[size_label])  # Maximum encryption time
        std_dev = statistics.stdev(run_times[size_label])  # Standard deviation of encryption times

        # Print the results for the current plaintext size
        print(f"Plaintext Size: {size_label} ({size_bytes} bytes)")
        print(f"Average Encryption Time: {format_time(avg_time)}")  # Display average time
        print(f"Minimum Encryption Time: {format_time(min_time)}")  # Display minimum time
        print(f"Maximum Encryption Time: {format_time(max_time)}")  # Display maximum time
        print(f"Standard Deviation: {format_time(std_dev)}\n")     # Display standard deviation

# Entry point of the script
if __name__ == "__main__":
    main()  # Execute the main function
