extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2, constant_time, error};
use self::rand::{SystemRandom, SecureRandom};


static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const KEY_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const HASH_LEN: usize = 32;
const PBKDF2_ITERS: u32 = 100000;


pub struct Crypto {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    key_hash: digest::Digest,
    cipher_key: [u8; KEY_LEN],
}


impl Crypto {
    fn new<'a, T: Into<Option<[u8; SALT_LEN]>>, V: Into<Option<[u8; NONCE_LEN]>>>
            (password: &'a str, salt: T, nonce: V) -> Crypto {
        let mut salt = salt.into().unwrap_or([0; SALT_LEN]);
        Crypto::get_random_bytes(&mut salt);

        let mut nonce = nonce.into().unwrap_or([0; NONCE_LEN]);
        Crypto::get_random_bytes(&mut nonce);

        let mut cipher_key = [0; KEY_LEN];
        Crypto::derive_key(password, &salt, &mut cipher_key);

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
        constant_time::verify_slices_are_equal(given_key_hash.as_ref(), file_key_hash)
    }

    fn hash(msg: &[u8]) -> digest::Digest {
        digest::digest(DIGEST_ALG, msg)
    }

    /*fn aes_encrypt(&self, plaintext: &str) -> String {
        String::new()
    }
    
    fn aes_decrypt(&self, ciphertext: &str) -> String {
        String::new()
    }*/
}


#[cfg(test)]
mod tests {
    use super::*;
    // "test" in u8
    const test: [u8; 4] = [116, 101, 115, 116];

    #[test]
    fn sha256_hashing() {
        // Compute SHA256("test")
        let expected: [u8; HASH_LEN] = [159, 134, 208, 129, 136, 76, 125, 101,
                                        154, 47, 234, 160, 197, 90, 208, 21, 
                                        163, 191, 79, 27, 43, 11, 130, 44, 209,
                                        93, 108, 21, 176, 240, 10, 8];
        let actual = Crypto::hash(&test);
        assert_eq!(expected, actual.as_ref());
    }
    
    #[test]
    fn pbkdf2_derivation() {
        let expected: [u8; KEY_LEN] = [42, 66, 208, 104, 253, 187, 180, 77,
                                       116, 163, 197, 229, 140, 43, 253, 234];    
        let salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2];
        let mut actual = [0; KEY_LEN];
        Crypto::derive_key("test", &salt, &mut actual);
        assert_eq!(expected, actual);
    }
}




