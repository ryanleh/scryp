# Simple Crypto
###### A simple AES file encryptor/decryptor with PyCrypto

All of the free file encryptors I found online either were way too feature-packed or didn't handle encrypting multiple files well so I decided to make my own.  

#### Encryption works as follows:  
1. Generate random 128 bit cipher key
2. Generate random salt and create second key by applying PBKDF2-HMAC-SHA256 to user-provided password + salt
3. Encrypt data key with cipher key using 128-bit AES-CTR
4. Generate MAC of ciphertext
5. Hash cipher key 
6. Store salt, hash, IV, MAC, and ciphertext

#### Decryption works as follows:
1. Apply PBKDF2-HMAC-SHA256 to user-provided password + salt in file to generate a new cipher key
2. Check that the hash of the new cipher key matches the hash in the file
3. Verify the MAC
4. Decrypt the file

#### Random notes to keep in mind:
* Doesn't support file paths so you have to be in the same directory as the file you're encrypt/decrypting
* I use a large number of PBKDF2 iterations since personally the files I'm encrypting are small... you may want to change this
* Currently only supports text files... Planning to allow for other file types
  later
