extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2, constant_time, error};
use self::rand::{SystemRandom, SecureRandom};
use self::error::Unspecified as CryptoError;

static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
// TODO: Fix nonce parameters
const NONCE_LEN: usize = 12;
const HASH_LEN: usize = 32;
const PBKDF2_ITERS: u32 = 300000;


pub struct Crypto {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    key_hash: [u8; HASH_LEN],
    key: [u8; KEY_LEN],
}


impl Crypto {
    pub fn new<'a, T: Into<Option<[u8; SALT_LEN]>>, V: Into<Option<[u8; NONCE_LEN]>>>
            (password: &'a str, salt: T, nonce: V) -> Crypto {
        let mut salt = match salt.into() {
            Some(s) => s,
            None => {
                let mut temp = [0; SALT_LEN];
                Crypto::get_random_bytes(&mut temp);
                temp
            },
        };
            
        let mut nonce = match nonce.into() {
            Some(s) => s,
            None => {
                let mut temp = [0; NONCE_LEN];
                Crypto::get_random_bytes(&mut temp);
                temp
            },
        };

        let mut key = [0; KEY_LEN];
        Crypto::derive_key(password, &salt, &mut key);

        let key_hash = Crypto::hash(&key);

        Crypto { salt, nonce, key_hash, key }
    }
    
    fn get_random_bytes(dest: &mut [u8]) {
        let random = SystemRandom::new();
        random.fill(dest)
            .expect("Failed to fill dest");
    }

    fn derive_key(password: &str, salt: &[u8; SALT_LEN], dest: &mut [u8]) {
        pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERS, salt, password.as_bytes(), dest);
    }

    pub fn verify_key(&self, file_key_hash: &[u8; HASH_LEN]) -> Result<(), error::Unspecified> {
        constant_time::verify_slices_are_equal(&self.key_hash, file_key_hash)
    }

    fn hash(msg: &[u8]) -> [u8; HASH_LEN] {
        let mut hash = [0; HASH_LEN];
        let hash_digest = digest::digest(DIGEST_ALG, msg);
        hash.copy_from_slice(&hash_digest.as_ref()[0..HASH_LEN]);
        hash
    }

    // Perhaps find a better way to handle memory here?
    // TODO: Change naming
    fn aes_encrypt<'a>(&self, mut plaintext: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let seal_key = aead::SealingKey::new(AEAD_ALG, &self.key)
            .expect("Seal keygen failed");
        let size = aead::seal_in_place(&seal_key, &self.nonce, &[], &mut plaintext, TAG_LEN)
            .expect("Seal failed");
        Ok(&plaintext[..size])
    }
    
    fn aes_decrypt<'a>(&self, ciphertext: &'a mut [u8]) -> Result<&'a mut [u8], CryptoError> {
        let open_key = aead::OpeningKey::new(AEAD_ALG, &self.key)
            .expect("Open keygen failed");
        aead::open_in_place(&open_key, &self.nonce, &[], 0, ciphertext)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // "test" in u8
    const test: [u8; 4] = [116, 101, 115, 116];
    const salt: [u8; SALT_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2];
    const nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
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

    #[test]
    fn test_aes_encrypt() {
        let crypto = Crypto::new("test", salt, nonce); 
        let mut correct = [161, 199, 190, 204, 106, 148, 112, 203, 127, 207, 65, 77, 59, 48, 130, 
                           165, 228, 1, 28, 204];
        let msg: String = "test".to_string();
        let mut ciphertext: Vec<u8> = vec![0;msg.len()+TAG_LEN];
        ciphertext[..msg.len()].copy_from_slice(msg.as_bytes());
        let actual = crypto.aes_encrypt(&mut ciphertext).unwrap();
        assert_eq!(correct, actual);
        
    }

    #[test]
    fn test_aes_decrypt() {
        let crypto = Crypto::new("test", salt, nonce); 
        let correct = "test".to_string();
        let mut ciphertext = [161, 199, 190, 204, 106, 148, 112, 203, 127, 207, 65, 77, 59, 48,
                              130, 165, 228, 1, 28, 204];
        let plaintext = crypto.aes_decrypt(&mut ciphertext).unwrap();
        assert_eq!(correct.as_bytes(), plaintext);
    }
}




