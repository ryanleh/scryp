extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2, constant_time, error};
use self::rand::{SystemRandom, SecureRandom};


static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const KEY_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const HASH_LEN: usize = 16;
const PBKDF2_ITERS: u32 = 100000;


pub struct Crypto {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    key_hash: digest::Digest,
    cipher_key: [u8; KEY_LEN],
}


impl Crypto {
    // TODO: add support for choosing hash
    fn new<'a, T: Into<Option<[u8; SALT_LEN]>>,
           V: Into<Option<[u8; NONCE_LEN]>>>(&self, password: &'a str, salt: T,
                                             nonce: V) -> Crypto {
        let mut salt = salt.into().unwrap_or([0; SALT_LEN]);
        self.get_random_bytes(&mut salt);

        let mut nonce = nonce.into().unwrap_or([0; NONCE_LEN]);
        self.get_random_bytes(&mut nonce);
        
        let mut cipher_key = [0; KEY_LEN];
        self.derive_key(password, &mut cipher_key);

        let key_hash = self.hash(&cipher_key);

        Crypto {
                salt,
                nonce,
                key_hash,
                cipher_key,
        }
    }
    
    fn get_random_bytes(&self, dest: &mut [u8]) {
        let random = SystemRandom::new();
        random.fill(dest)
            .expect("Failed to fill dest");
    }

    fn derive_key(&self, password: &str, dest: &mut [u8]) {
        pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERS, &self.salt,
                       password.as_bytes(), dest);
    }

    fn verify_key(&self, password: &str, file_key_hash: &[u8; HASH_LEN]) -> Result<(), error::Unspecified> {
        let mut given_key = [0; KEY_LEN];
        self.derive_key(password, &mut given_key);
        let given_key_hash = self.hash(&given_key);
        constant_time::verify_slices_are_equal(given_key_hash.as_ref(), file_key_hash)
    }

    fn hash(&self, msg: &[u8]) -> digest::Digest {
        digest::digest(DIGEST_ALG, msg)
    }

    /*fn aes_encrypt(&self, plaintext: &str) -> String {
        String::new()
    }
    
    fn aes_decrypt(&self, ciphertext: &str) -> String {
        String::new()
    }*/
}
