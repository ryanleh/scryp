# Simple Crypto
###### A simple AES file encryptor/decryptor with PyCrypto

All of the free file encryptors I found online either were way too feature-packed or didn't handle encrypting multiple files well so I decided to make my own.  

#### Encryption works as follows:  
1. Generate 32-byte key by applying PBKDF2-HMAC-SHA256 to user-provided password + random salt
2. Split key into 16-byte K<sub>AES</sub> and K<sub>MAC</sub>
3. Encrypt data under K<sub>AES</sub> using 128-bit AES-CTR with random 12-byte nonce and 4-byte counter &asymp; 68Gb encryption limit
4. Generate tag of {filename || nonce || encrypted data} under K<sub>MAC</sub> using HMAC-SHA256
5. Hash K<sub>AES</sub> || K<sub>MAC</sub> with SHA256
6. Store salt, hash, tag, filename, nonce and encrypted data

#### Decryption works as follows:
1. Apply PBKDF2-HMAC-SHA256 to user-provided password + salt in file to regenerate key
2. Check that the hash of the new key matches the file-provided hash
3. Verify the tag with re-derived K<sub>MAC</sub>
4. Decrypt the file with re-derived K<sub>AES</sub> and given nonce

#### Random notes to keep in mind:
* Doesn't support file paths so you have to be in the same directory as the file you're encrypt/decrypting
* I use a large number of PBKDF2 iterations since personally the files I'm encrypting are small... you may want to change this
* Currently only supports text files... Planning to allow for other file types
  later
