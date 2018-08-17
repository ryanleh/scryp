# Simple Crypto
###### A simple AES file encryptor/decrypt

A pet project to gain experience using cryptographic libraries in Python and Rust.

DISCLAIMER: Use at your own risk.  While I have tried to follow best practices, this program has not been thouroughly tested to be secure

#### Encryption works as follows:  
1. Generate 32-byte key by applying PBKDF2-HMAC-SHA256 to user-provided password with a random 16-byte salt
2. Encrypt data under key using 256-bit AES-GCM with a random 12-byte nonce and the filename as additional authentication data
3. Hash key with SHA256
4. Store filename, salt, hash, nonce, and encrypted data

#### Decryption works as follows:
1. Apply PBKDF2-HMAC-SHA256 to user-provided password + salt in file to regenerate key
2. Check that the hash of the new key matches the file-provided hash
3. Decrypt the file with using re-derived key, ciphertext, nonce, and filename

#### Notes:
* I use a large number of PBKDF2 iterations since the files I'm encrypting are small... you may want to change this
* Python and Rust versions support parallel encryption/decryption of multiple files
