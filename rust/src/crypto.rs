extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2, constant_time, error};
use self::rand::{SystemRandom, SecureRandom};
use self::error::Unspecified as CryptoError;

static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HASH_LEN: usize = 32;
const PBKDF2_ITERS: u32 = 300000;
const TAG_LEN: usize = 16;
pub const PARAMS_LEN: usize = SALT_LEN + HASH_LEN + NONCE_LEN;


pub struct Crypto {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    key_hash: [u8; HASH_LEN],
    key: [u8; KEY_LEN],
}


impl Crypto {
    pub fn new<'a> (password: &'a str,
                    salt: Option<[u8; SALT_LEN]>, 
                    nonce: Option<[u8; NONCE_LEN]>) -> Crypto {
        // Match salt to provided input or randomness
        let salt = match salt {
            Some(s) => s,
            None => {
                let mut temp = [0; SALT_LEN];
                Crypto::get_random_bytes(&mut temp)
                    .expect("Failed to generate random bytes for salt");
                temp
            },
        };
        // Match nonce to provided input or randomness
        let nonce = match nonce.into() {
            Some(s) => s,
            None => {
                let mut temp = [0; NONCE_LEN];
                Crypto::get_random_bytes(&mut temp)
                    .expect("Failed to generate random bytes for nonce");
                temp
            },
        };
        // Use PBKDF2 to derive key and hash it
        let mut key = [0; KEY_LEN];
        Crypto::derive_key(password, &salt, &mut key);

        let key_hash = Crypto::hash(&key);

        Crypto { salt, nonce, key_hash, key }
    }
    
    fn get_random_bytes(dest: &mut [u8]) -> Result<(), CryptoError> {
        let random = SystemRandom::new();
        random.fill(dest)?;
        Ok(())
    }

    fn derive_key(password: &str, salt: &[u8; SALT_LEN], dest: &mut [u8]) {
        pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERS, salt, password.as_bytes(), dest);
    }

    
    fn hash(msg: &[u8]) -> [u8; HASH_LEN] {
        let mut hash = [0; HASH_LEN];
        let hash_digest = digest::digest(DIGEST_ALG, msg);
        hash.copy_from_slice(&hash_digest.as_ref()[0..HASH_LEN]);
        hash
    }

    pub fn verify_key(&self, file_key_hash: &[u8; HASH_LEN]) -> Result<(), CryptoError> {
        constant_time::verify_slices_are_equal(&self.key_hash, file_key_hash)
    }

    // TODO: Change naming
    pub fn aes_encrypt<'a>(&self, plaintext: &[u8], ciphertext: &'a mut Vec<u8>, filename: &str) 
            -> Result<(), CryptoError> {
        // Since seal_in_place rewrites the original plaintext vector to store ciphertext, we have
        // to copy the plaintext into the ciphertext vector and add space for the tag
        ciphertext.extend_from_slice(plaintext);
        ciphertext.extend_from_slice(&[0;TAG_LEN]);

        let seal_key = aead::SealingKey::new(AEAD_ALG, &self.key)?;
        aead::seal_in_place(&seal_key, &self.nonce, filename.as_bytes(), ciphertext, TAG_LEN)?;
        Ok(())
    }
   
    /// Decrypts and authenticates the ciphertext in place and returns a slice containing
    /// the plaintext
    pub fn aes_decrypt<'a>(&self, ciphertext: &'a mut [u8], filename: &str) 
            -> Result<&'a mut [u8], CryptoError> {
        let open_key = aead::OpeningKey::new(AEAD_ALG, &self.key)?;
        aead::open_in_place(&open_key, &self.nonce, filename.as_bytes(), 0, ciphertext)
    }

    pub fn params(&self) -> [u8; PARAMS_LEN] {
        let mut params: [u8; PARAMS_LEN] = [0; PARAMS_LEN];
        params[..SALT_LEN].copy_from_slice(&self.salt);
        params[SALT_LEN..SALT_LEN+HASH_LEN].copy_from_slice(&self.key_hash);
        params[SALT_LEN+HASH_LEN..].copy_from_slice(&self.nonce);
        params
    }

    pub fn from_params(password: &str, params: &[u8]) -> Result<Crypto, CryptoError> {
        let mut salt = [0; SALT_LEN];
        let mut key_hash = [0; HASH_LEN];
        let mut nonce = [0; NONCE_LEN];

        salt.copy_from_slice(&params[..SALT_LEN]);
        key_hash.copy_from_slice(&params[SALT_LEN..SALT_LEN+HASH_LEN]);
        nonce.copy_from_slice(&params[SALT_LEN+HASH_LEN..PARAMS_LEN]);

        let crypto = Crypto::new(password, salt, nonce);
        crypto.verify_key(&key_hash)?;
        Ok(crypto)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // "test" in u8
    const test: [u8; 4] = [116, 101, 115, 116];
    const salt: [u8; SALT_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2];
    const nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
    const filename: &str = "test.txt";

    #[test]
    fn test_hash() {
        // Compute SHA256("test")
        let expected: [u8; HASH_LEN] = [159, 134, 208, 129, 136, 76, 125, 101,
                                        154, 47, 234, 160, 197, 90, 208, 21, 
                                        163, 191, 79, 27, 43, 11, 130, 44, 209,
                                        93, 108, 21, 176, 240, 10, 8];
        let actual = Crypto::hash(&test);
        assert_eq!(expected, actual.as_ref());
    }
    
    #[test]
    fn test_derive_key() {
        let expected: [u8; KEY_LEN] = [241, 38, 124, 132, 21, 185, 197, 23, 136, 236, 178, 
                                       62, 212, 44, 248, 227, 0, 225, 58, 160, 25, 62, 112, 
                                       147, 98, 197, 141, 104, 22, 214, 232, 18];
        let mut actual = [0; KEY_LEN];
        Crypto::derive_key("test", &salt, &mut actual);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_verify_key() {
        let correct: [u8; KEY_LEN] = [241, 38, 124, 132, 21, 185, 197, 23, 136, 236, 178, 
                                       62, 212, 44, 248, 227, 0, 225, 58, 160, 25, 62, 112, 
                                       147, 98, 197, 141, 104, 22, 214, 232, 18];
        let correct_hash = Crypto::hash(&correct);
        let crypto = Crypto::new("test", salt, None);
        let result = crypto.verify_key(&correct_hash);
        assert_eq!(result.unwrap(), ());
    }

    #[test]
    #[should_panic]
    fn test_verify_incorrect_key() {
        let incorrect: [u8; KEY_LEN] = [240, 38, 124, 132, 21, 185, 197, 23, 136, 236, 178, 
                                       62, 212, 44, 248, 227, 0, 225, 58, 160, 25, 62, 112, 
                                       147, 98, 197, 141, 104, 22, 214, 232, 18];
        let incorrect_hash = Crypto::hash(&incorrect);
        let crypto = Crypto::new("test", salt, None);
        let result = crypto.verify_key(&incorrect_hash);
        result.unwrap();
    }

     /*let mut ciphertext = [161, 199, 190, 204, 106, 148, 112, 203, 127, 207, 65, 77, 59, 48,
                              130, 165, 228, 1, 28, 204];*/

    #[test]
    fn test_aes_encrypt() {
        let crypto = Crypto::new("test", salt, nonce); 
        let correct = [161, 199, 190, 204, 58, 189, 4, 240, 55, 139, 246, 96, 177, 30, 206, 
                       230, 234, 117, 164, 93];
        let msg: String = "test".to_string();
        let mut ciphertext: Vec<u8> = Vec::new();
        let actual = crypto.aes_encrypt(msg.as_bytes(), &mut ciphertext, filename).unwrap();
        assert_eq!(correct, actual);
        
    }

    #[test]
    fn test_aes_decrypt() {
        let crypto = Crypto::new("test", salt, nonce); 
        let correct = "test".to_string();
        let mut ciphertext = [161, 199, 190, 204, 58, 189, 4, 240, 55, 139, 246, 96, 177, 
                              30, 206, 230, 234, 117, 164, 93];
        let plaintext = crypto.aes_decrypt(&mut ciphertext, filename).unwrap();
        assert_eq!(correct.as_bytes(), plaintext);
    }
}




