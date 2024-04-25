# Simple encryption algorithms

Related article: [https://bit.ly/3WfKXWK](https://bit.ly/3WfKXWK)

## Contents

- Caesar cipher
- Vigenère cipher
- Bitwise rotation
- XOR encryption

## Usage

Replace 'cipher' for the appropriate word.

To encrypt:

```bash
python3 cipher.py file_to_encrypt key
```

To decrypt, use the '**-d**' flag (not necessary when using **xor.py**):

```bash
python3 cipher.py -d file_to_decrypt key
```

Optionally, you can specify the output file with '**-o**':

```bash
python3 cipher.py file_to_encrypt key -o output_file
```

To see the help use '**-h**':

```bash
python3 cipher.py -h
```

Alternatively, you can import the individual functions to play with them in your Python programs:

```python
from cipher import cipher
```

Lastly, the key should be a string in the case of **vigenere.py** or **xor.py**, and an integer in the case of **caesar.py** and **bitwise.py**.
