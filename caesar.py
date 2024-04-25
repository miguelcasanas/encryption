# Caesar cipher encryption/decryption
# Author: Miguel Casañas
# Contact: https://t.me/miguelcasanas
# Date: April 2024

if __name__ == "__main__":
    import argparse
    import os
    import sys

def caesar(plaintext: bytes, key: int=128, decrypt: bool=False) -> bytes:
    """
    Encrypts or decrypts binary data using a Caesar cipher approach.

    This function applies a Caesar cipher, which shifts each byte in the given data by a specified key.
    If 'decrypt' is True, the shift is reversed to decrypt the data. If 'decrypt' is False, it encrypts the data.
    The key specifies the number of positions each byte should be shifted. 

    Parameters:
        plaintext (bytes): The binary data to be encrypted or decrypted. It must not be empty.
        key (int): The shift key. It must not be zero or a multiple of 256.
        decrypt (bool): If True, decrypts the data. If False, encrypts the data.

    Returns:
        bytes: The encrypted or decrypted data.

    Raises:
        TypeError: If 'plaintext' is not of type 'bytes', 'key' is not an 'int', or 'decrypt' is not a 'bool'.
        ValueError: If 'plaintext' is empty or 'key' is zero or a multiple of 256.

    Example:
        # Encrypting data
        plaintext = b"Hello, World!"
        key = 3
        ciphertext = caesar(plaintext, key)

        # Decrypting data
        decrypted = caesar(ciphertext, key, decrypt=True)
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
    if key % 256 == 0:
        raise ValueError("The 'key' argument must not be zero or a multiple of 256")

    # Choose sign to encrypt/decrypt
    sign = -1 if decrypt else 1

    # Byte transformation
    new_byte = lambda byte: (byte + sign * key) % 256
    ciphertext = bytes(map(new_byte, plaintext))

    return ciphertext

if __name__ == "__main__":
    description = (
        "Encrypt/decrypt a file using Caesar cipher (for educational purposes only)\n"
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
    
    if args.key % 256 == 0:
        print(f"Error: The key cannot be zero or a multiple of 256.", file=sys.stderr)
        sys.exit(1)
    
    output = args.output or args.input + ".cae"
    
    try:
        with open(args.input, "rb") as f:
            plaintext = f.read()
        ciphertext = caesar(plaintext, args.key, args.decrypt)
        with open(output, "wb") as f:
            f.write(ciphertext)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print("Done!")