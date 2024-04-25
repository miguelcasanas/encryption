# Bitwise rotation encryption/decryption
# Author: Miguel Casañas
# Contact: https://t.me/miguelcasanas
# Date: April 2024

if __name__ == "__main__":
    import argparse
    import os
    import sys

def bitwise(plaintext: bytes, key: int=4, decrypt: bool=False) -> bytes:
    """
    Encrypts or decrypts binary data using bitwise rotation.

    This function applies a bitwise rotation to each byte in the 'plaintext'. It rotates 
    the bits to the right or left based on the 'key' and whether 'decrypt' is set to 
    True or False. This transformation can be used for both encryption and decryption,
    depending on the direction of rotation and the specified 'key'.

    Parameters:
        plaintext (bytes): The binary data to be encrypted or decrypted. Must not be empty.
        key (int): The number of bit positions to rotate for encryption/decryption.
        decrypt (bool): If True, rotates bits to the left to decrypt; if False, rotates bits to the right to encrypt.

    Returns:
        bytes: The encrypted or decrypted data.

    Raises:
        TypeError: If 'plaintext' is not a bytes object, 'key' is not an integer, or 'decrypt' is not a boolean.
        ValueError: If 'plaintext' is empty or 'key' is zero or a multiple of 8.

    Example:
        # Encrypting data
        plaintext = b"Hello"
        key = 4
        ciphertext = bitwise(plaintext, key)

        # Decrypting data
        decrypted = bitwise(ciphertext, key, decrypt=True)
        assert decrypted == plaintext
    """
    # Type checks
    if not isinstance(plaintext, bytes):
        raise TypeError("Expected 'plaintext' to be of type 'bytes'")
    if not isinstance(key, int):
        raise TypeError("Expected 'key' to be of type 'int'")
    if not isinstance(decrypt, bool):
        raise TypeError("Expected 'decrypt' to be of type 'bool'")
    
    # Value checks
    if len(plaintext) == 0:
        raise ValueError("The 'plaintext' argument must not be empty")
    if key % 8 == 0:
        raise ValueError("The 'key' argument must not be zero or a multiple of 8")

    # Choose sign to encrypt/decrypt
    key *= -1 if decrypt else 1

    # Byte transformation
    key %= 8
    new_byte = lambda byte: (byte >> key)| (byte << (8 - key) & 0xff)
    ciphertext = bytes(map(new_byte, plaintext))

    return ciphertext

if __name__ == "__main__":
    description = (
        "Encrypt/decrypt a file using bitwise rotation (for educational purposes only)\n"
        "Author: Miguel Casañas\n"
        "Contact: https://t.me/miguelcasanas\n"
        "Date: April 2024"
    )
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="file to encrypt/decrypt")
    parser.add_argument("key", help="encryption key", type=int)
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("-d", "--decrypt", help="decrypt mode", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: The file '{args.input}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    if args.key % 8 == 0:
        print(f"Error: The key cannot be zero or a multiple of 8.", file=sys.stderr)
        sys.exit(1)
    
    output = args.output or args.input + ".btw"
    
    try:
        with open(args.input, "rb") as f:
            plaintext = f.read()
        ciphertext = bitwise(plaintext, args.key, args.decrypt)
        with open(output, "wb") as f:
            f.write(ciphertext)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print("Done!")