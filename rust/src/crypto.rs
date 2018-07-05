use std::error::Error;

extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2};
use self::rand::{SystemRandom, SecureRandom};

static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const KEY_LEN: usize = 16;
const PBKDF2_ITERS: u32 = 100000;


pub struct Crypto {
    salt: [u8; 16],
    nonce: [u8; 12],
    key_hash: digest::Digest,
    cipher_key: [u8; 16],
}


impl Crypto {
    // Weird func sig because of poor optional argument support
    // TODO: add support for choosing hash
    fn new<'a>(&self, password: &'a str) -> Crypto {
        let mut salt = [0; 16];
        self.get_random_bytes(&mut salt);
        let mut nonce = [0; 12];
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

    /*fn verify_key(&self, password: &str) -> Result<(), Error> {
        Some(())
    }*/

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
