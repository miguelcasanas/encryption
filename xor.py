# XOR encryption/decryption
# Author: Miguel Casañas
# Contact: https://t.me/miguelcasanas
# Date: April 2024

if __name__ == "__main__":
    import argparse
    import os
    import sys

def xor(plaintext: bytes, key: str) -> bytes:
    """
    Encrypts or decrypts data using the XOR (exclusive OR) operation with a given key.

    The XOR operation is performed on each byte of the input data with the corresponding
    byte from the key, repeating the key as needed to match the data's length. This function
    can be used for both encryption and decryption, as applying XOR twice returns the
    original data.

    Parameters:
        plaintext (bytes): The input data to be encrypted or decrypted.
        key (str): The key used for the XOR operation. Must be a non-empty string.

    Returns:
        bytes: The encrypted or decrypted output, depending on the context.

    Raises:
        TypeError: If 'plaintext' is not a bytes object or 'key' is not a string.
        ValueError: If 'plaintext' or 'key' is empty.

    Example:
        # Encrypting data
        plaintext = b"Hello, World!"
        key = "qwerty"
        ciphertext = xor(plaintext, key)

        # Decrypting data
        decrypted = xor(ciphertext, key)
        assert decrypted == plaintext
    """
    # Type checks
    if not isinstance(plaintext, bytes):
        raise TypeError("Expected 'plaintext' to be of type 'bytes'")
    if not isinstance(key, str):
        raise TypeError("Expected 'key' to be of type 'str'")

    # Check for non-empty inputs
    if len(plaintext) == 0:
        raise ValueError("The 'plaintext' argument must not be empty")
    if len(key) == 0:
        raise ValueError("The 'key' argument must not be empty")

    # Encode key to bytes
    key_bytes = key.encode()

    # XOR operation
    new_byte = lambda byte, i: byte ^ key_bytes[i % len(key_bytes)]
    ciphertext = bytes(map(new_byte, plaintext, range(len(plaintext))))

    return ciphertext

if __name__ == "__main__":
    description = (
        "Encrypt/decrypt a file using XOR (for educational purposes only)\n"
        "Author: Miguel Casañas\n"
        "Contact: https://t.me/miguelcasanas\n"
        "Date: April 2024"
    )
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="file to encrypt/decrypt")
    parser.add_argument("key", help="encryption key")
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: The file '{args.input}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    if len(args.key) == 0:
        print(f"Error: The key cannot be an empty string.", file=sys.stderr)
        sys.exit(1)
    
    output = args.output or args.input + ".xor"
    
    try:
        with open(args.input, "rb") as f:
            plaintext = f.read()
        ciphertext = xor(plaintext, args.key)
        with open(output, "wb") as f:
            f.write(ciphertext)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print("Done!")