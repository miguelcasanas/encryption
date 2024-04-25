# Vigenère cipher encryption/decryption
# Author: Miguel Casañas
# Contact: https://t.me/miguelcasanas
# Date: April 2024

if __name__ == "__main__":
    import argparse
    import os
    import sys

def vigenere(plaintext: bytes, key: str, decrypt: bool=False) -> bytes:
    """
    Encrypts or decrypts binary data using the Vigenère cipher.

    This function applies the Vigenère cipher, which uses a repeating key to perform a Caesar cipher-like 
    transformation on the given plaintext. The shift for each byte is determined by the corresponding byte in 
    the repeating key. If 'decrypt' is True, the shift is reversed to decrypt the data. Otherwise, it encrypts
    the data.

    Parameters:
        plaintext (bytes): The binary data to be encrypted or decrypted. Must not be empty.
        key (str): The encryption/decryption key as a string. Must not be empty.
        decrypt (bool): If True, decrypts the data; if False, encrypts the data.

    Returns:
        bytes: The encrypted or decrypted output.

    Raises:
        TypeError: If 'plaintext' is not of type 'bytes', 'key' is not a 'str', or 'decrypt' is not a 'bool'.
        ValueError: If 'plaintext' or 'key' is empty.

    Example:
        # Encrypting data
        plaintext = b"Hello, World!"
        key = "qwerty"
        ciphertext = vigenere(plaintext, key)

        # Decrypting data
        decrypted = vigenere(ciphertext, key, decrypt=True)
        assert decrypted == plaintext
    """
    # Type checks
    if not isinstance(plaintext, bytes):
        raise TypeError("Expected 'plaintext' to be of type 'bytes'")
    if not isinstance(key, str):
        raise TypeError("Expected 'key' to be of type 'str'")
    if not isinstance(decrypt, bool):
        raise TypeError("Expected 'decrypt' to be of type 'bool'")

    # Check for non-empty inputs
    if len(plaintext) == 0:
        raise ValueError("The 'plaintext' argument must not be empty")
    if len(key) == 0:
        raise ValueError("The 'key' argument must not be empty")

    # Encode key to bytes
    key_bytes = key.encode()

    # Choose sign to encrypt/decrypt
    sign = -1 if decrypt else 1

    # Vigenère cipher
    new_byte = lambda byte, i: (byte + sign * key_bytes[i % len(key_bytes)]) % 256
    ciphertext = bytes(map(new_byte, plaintext, range(len(plaintext))))

    return ciphertext

if __name__ == "__main__":
    description = (
        "Encrypt/decrypt a file using Vigenère cipher (for educational purposes only)\n"
        "Author: Miguel Casañas\n"
        "Contact: https://t.me/miguelcasanas\n"
        "Date: April 2024"
    )
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="file to encrypt/decrypt")
    parser.add_argument("key", help="encryption key")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("-d", "--decrypt", help="decrypt mode", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: The file '{args.input}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    if len(args.key) == 0:
        print(f"Error: The key cannot be an empty string.", file=sys.stderr)
        sys.exit(1)
    
    output = args.output or args.input + ".vig"
    
    try:
        with open(args.input, "rb") as f:
            plaintext = f.read()
        ciphertext = vigenere(plaintext, args.key, args.decrypt)
        with open(output, "wb") as f:
            f.write(ciphertext)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print("Done!")