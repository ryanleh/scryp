extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2, constant_time, error};
use self::rand::{SystemRandom, SecureRandom};
use self::error::Unspecified as CryptoError;

use Operation;

static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const TAG_LEN: usize = aead::MAX_TAG_LEN;
const KEY_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const HASH_LEN: usize = 32;
const PBKDF2_ITERS: u32 = 300000;


pub struct Crypto<T> {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    key_hash: [u8; HASH_LEN],
    cipher_key: T,
}


impl Crypto {
    fn new<'a, T: Into<Option<[u8; SALT_LEN]>>, V: Into<Option<[u8; NONCE_LEN]>>>
            (password: &'a str, operation: Operation, salt: T, nonce: V) -> Crypto {
        let mut salt = salt.into().unwrap_or([0; SALT_LEN]);
        Crypto::get_random_bytes(&mut salt);

        let mut nonce = nonce.into().unwrap_or([0; NONCE_LEN]);
        Crypto::get_random_bytes(&mut nonce);

        let mut key = [0; KEY_LEN];
        Crypto::derive_key(password, &salt, &mut key);
        let cipher_key = match operation {
            ENCRYPT => 

        let key_hash = Crypto::hash(&cipher_key);

        Crypto { salt, nonce, key_hash, cipher_key }
    }
    
    fn get_random_bytes(dest: &mut [u8]) {
        let random = SystemRandom::new();
        random.fill(dest)
            .expect("Failed to fill dest");
    }

    fn derive_key(password: &str, salt: &[u8; SALT_LEN], dest: &mut [u8]) {
        pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERS, salt, password.as_bytes(), dest);
    }

    fn verify_key(password: &str, salt: &[u8; SALT_LEN], file_key_hash: &[u8; HASH_LEN]) 
            -> Result<(), error::Unspecified> {
        let mut given_key = [0; KEY_LEN];
        Crypto::derive_key(password, salt, &mut given_key);
        let given_key_hash = Crypto::hash(&given_key);
        constant_time::verify_slices_are_equal(&given_key_hash, file_key_hash)
    }

    fn hash(msg: &[u8]) -> [u8; HASH_LEN] {
        let mut hash = [0; HASH_LEN];
        let hash_digest = digest::digest(DIGEST_ALG, msg);
        hash.copy_from_slice(&hash_digest.as_ref()[0..HASH_LEN]);
        hash
    }

    // Perhaps find a better way to handle memory here?
    fn aes_encrypt<'a>(&self,ciphertext: &'a mut [u8]) -> Result<usize, CryptoError> {
        //aead::seal_in_place(&self.seal_key, &self.nonce, &[], &mut ciphertext, TAG_LEN)
        Ok(3)
    }
    
    fn aes_decrypt<'a>(&self, ciphertext: &'a mut [u8]) -> Result<&'a mut [u8], CryptoError> {
        Err(error::Unspecified)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // "test" in u8
    const test: [u8; 4] = [116, 101, 115, 116];
    const salt: [u8; SALT_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2];
    const nonce: [u8; NONCE_LEN] = [37, 134, 36, 162, 205, 16, 237, 253, 119, 102, 
                                    189, 36, 173, 122, 192, 107];

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
        let expected: [u8; KEY_LEN] = [241, 38, 124, 132, 21, 185, 197, 23, 136,
                                       236, 178, 62, 212, 44, 248, 227];
        let mut actual = [0; KEY_LEN];
        Crypto::derive_key("test", &salt, &mut actual);
        assert_eq!(expected, actual);
    }

    #[test]
    #[should_panic]
    fn test_verify_key() {
        let correct: [u8; KEY_LEN] = [241, 38, 124, 132, 21, 185, 197, 23, 136,
                                        236, 178, 62, 212, 44, 248, 227];
        let correct_hash = Crypto::hash(&correct);
        let result = Crypto::verify_key("test", &salt, &correct_hash);
        assert_eq!(result.unwrap(), ());

        let incorrect: [u8; KEY_LEN] = [240, 38, 124, 132, 21, 185, 197, 23, 136,
                                        236, 178, 62, 212, 44, 248, 227];
        let incorrect_hash = Crypto::hash(&incorrect);
        let result = Crypto::verify_key("test", &salt, &incorrect_hash);
        result.unwrap();
    }

    #[test]
    fn test_aes() {
        let correct = [139, 206, 129, 20, 238, 11, 138, 165, 185, 25, 216, 151, 80, 192, 44, 49, 
                   78, 31, 42, 168];
        let crypto = Crypto::new("test", salt, nonce); 
        let message: String = "test".to_string();
        let mut ciphertext: Vec<u8> = vec![0;message.len()+TAG_LEN];
        ciphertext[..msg.len()].copy_from_slice(msg.as_bytes());
        let actual = crypto.aes_encrypt(&mut ciphertext);
        assert_eq!(correct, actual);
        
        let correct = "test".to_string();
        let plaintext = crypto.aes_decrypt(actual).unwrap();
        assert_eq!(correct.as_bytes(), plaintext);
    }
}




