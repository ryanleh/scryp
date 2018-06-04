# Simple Crypto
###### A simple AES file encryptor/decryptor with PyCrypto

All of the free file encryptors I found online either were way too feature-packed or didn't handle encrypting multiple files well so I decided to make my own.  

#### Encryption works as follows:  
1. Generate random salt and key by applying PBKDF2-HMAC-SHA256 to user-provided password + salt
2. Hash generated key
3. Split key up into cipher and HMAC keys
4. Encrypt data with cipher key using 128-bit AES-CTR
5. Generate MAC of {filename, IV, ciphertext}
6. Store salt, hashed key, tag, filename, iv, ciphertext
#### Decryption works as follows:
1. Re-derive keys with PBKDF2-HMAC-SHA256 on user-provided password + salt
2. Check that the hash of the generated key matches the hash in the file
3. Verify the MAC
4. Decrypt the file

#### Random notes to keep in mind:
* Doesn't support file paths so you have to be in the same directory as the file you're encrypt/decrypting
* I use a large number of PBKDF2 iterations since personally the files I'm encrypting are small... you may want to change this
* Currently only supports text files... Planning to allow for other file types
  later
