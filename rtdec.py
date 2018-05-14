import argparse
import os
import binascii
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from Crypto.Util import Counter

"""
Following best practice:
1. Random 128 bit data key is generated
2. Generate random salt and create second key with
   given password and PBKDF2
3. Encrypt data key with user-generated key
4. Hash of user-generated key to check for correctness later
5. Store salt, encrypted data key, hash, and data
"""
# TODO: Check argument type checking


class CryptoError(Exception):
    """Exception raised for errors incorrect passwords

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


def make_parser():
    """Builds ArgumentParser Object"""
    parser = argparse.ArgumentParser(description=
                                     'Decrypt files using 128-bit AES')
    parser.add_argument('-f', '--filenames', required=True, nargs='+',
                        help='Files to decrypt', type=str)
    parser.add_argument('-p', '--password', required=True,
                        help='Password to decrypt with', type=str)
    parser.add_argument('-r', '--remove', required=False,
                        action='store_true',
                        help='Delete ciphertext file')
    return parser


def password_to_key(password, salt):
    """Runs PBKDF2 with 100000 iterations on provided password.

    Params:
      *  password (str): Password provided by user
      *  salt (byte str): Salt that password was encrypted with

    Returns:
      *  key (byte str): Result of PBKDF2 function on user's password
    """
    # 8-byte random salt
    print("Calling PBKDF2 with: " + str(salt) + " " + password)
    key = PBKDF2(password, salt, dkLen=16, count=100000,
                 prf=lambda key, salt: HMAC.new(key, salt, SHA256).digest())
    return key


def hash_key(key):
    """Hashes given key with one iteration of SHA256 and returns result

    Params:
      *  key (byte str): Result of PBKDF2 function on user's password

    Returns:
      *  key_hash (byte str)
    """
    return SHA256.SHA256Hash(key).digest()


def decrypt_file(key, iv, ciphertext):
    """Encrypts data using AES-CTR with provided key and data"""
    # Generate a new counter object for CTR mode
    counter = Counter.new(64, initial_value=1, prefix=iv)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    # TODO: have try catch here
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    cwd = os.getcwd()
    args = make_parser().parse_args()
    filenames = args.filenames
    password = args.password
    # Populate file streams
    file_streams = []
    for filename in filenames:
        try:
            name, extension = filename.split('.')
            if extension != "enc":
                raise TypeError(filename + " is not a valid ciphertext")
            file = open(cwd + '/' + filename, 'r')  # TODO: add optional delete
            file_streams.append((name, binascii.unhexlify(file.read())))
            file.close()
        except IOError:
            print("Given file: " + filename + " does not exist. Skipping")

    for file_stream in file_streams:
        salt = file_stream[1][:8]
        key_hash = file_stream[1][8:40]
        given_key = password_to_key(password, salt)
        if hash_key(given_key) != key_hash:
            raise CryptoError("Invalid password")
        iv = file_stream[1][40:48]
        ciphertext = file_stream[1][48:]
        plaintext = decrypt_file(given_key, iv, ciphertext)
        new_file = open(cwd + '/' + file_stream[0] + '.dec', 'w')
        new_file.write(str(plaintext, 'utf-8'))
        new_file.close()
        print("File: " + file_stream[0] + " decrypted!")
