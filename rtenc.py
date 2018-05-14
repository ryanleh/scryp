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


def make_parser():
    """Builds ArgumentParser Object"""
    parser = argparse.ArgumentParser(description=
                                     'Encrypt files using 128-bit AES')
    parser.add_argument('-f', '--filenames', required=True, nargs='+',
                        help='Files to encrypt', type=str)
    parser.add_argument('-p', '--password', required=True,
                        help='Password to encrypt with', type=str)
    parser.add_argument('-o', '--overwrite', required=False,
                        action='store_true',
                        help='Whether to delete original file')
    return parser


def get_random_bytes(n):
    """Returns n bytes of randomness"""
    return Random.new().read(n)


def generate_salt():
    """Generate an n-byte alnum salt with 190 bits of entropy"""
    alnum = ''.join(c for c in map(chr, range(256)) if c.isalnum())
    return ''.join(random.choice(alnum) for _ in range(32))


def password_to_key(password):
    """Runs PBKDF2 with 100000 iterations on provided password.

    Params:
      *  password (str): Password provided by user

    Returns:
      *  salt (byte str): random 8-bytes
      *  key (byte str): Result of PBKDF2 function on user's password
    """
    # 8-byte random salt
    salt = get_random_bytes(8)
    key = PBKDF2(password, salt, dkLen=16, count=100000,
                 prf=lambda key, salt: HMAC.new(key, salt, SHA256).digest())
    return salt, key


def hash_key(key):
    """Hashes given key with one iteration of SHA256 and returns result

    Params:
      *  key (byte str): Result of PBKDF2 function on user's password

    Returns:
      *  key_hash (byte str)
    """
    return SHA256.SHA256Hash(key).digest()


def encrypt_file(key, data):
    """Encrypts data using AES-CTR with provided key and data

    Params:
      *  key (byte str): Result of PBKDF2 function on user's password
      *  data (byte str): byte encoding of file contents

    Returns:
      *  iv (byte str): 8-bytes of randomness
      *  encrypted_data (byte str): Result of AES-CTR
    """
    iv = get_random_bytes(8)
    # Generate a new counter object for CTR mode
    counter = Counter.new(64, initial_value=1, prefix=iv)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    # TODO: have try catch here
    return iv, cipher.encrypt(data)


if __name__ == "__main__":
    cwd = os.getcwd()
    args = make_parser().parse_args()
    filenames = args.filenames
    password = args.password
    # Populate file streams
    file_streams = []
    for filename in filenames:
        try:
            file = open(cwd + '/' + filename, 'r')  # TODO: add optional delete
            file_streams.append((filename.split('.')[0],
                                bytes(file.read(), 'utf-8')))
            file.close()
        except IOError:
            print("Given file: " + filename + " does not exist. Skipping")

    for file_stream in file_streams:
        salt, key = password_to_key(password)
        key_hash = hash_key(key)
        iv, encrypted_stream = encrypt_file(key, file_stream[1])
        to_write = salt + key_hash + iv + encrypted_stream
        new_file = open(cwd + '/' + file_stream[0] + '.enc', 'bw')
        new_file.write(binascii.hexlify(to_write))
        new_file.close()
        print("File: " + file_stream[0] + " encrypted!")
