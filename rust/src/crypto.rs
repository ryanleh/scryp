extern crate ring;
use self::ring::{aead, digest, rand, pbkdf2};
use self::rand::{SystemRandom, SecureRandom};

static AEAD_ALG: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;


pub struct Crypto {
    salt: [u8; 16],
    nonce: [u8; 12],
    key_hash: [u8; 32],
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
        Crypto {
                salt,
                nonce,
                key_hash: [0; 32],
                cipher_key: [0; 32],
        }
    }
    
    fn get_random_bytes(&self, dest: &mut [u8]) {
        let random = SystemRandom::new();
        random.fill(dest)
            .expect("Failed to fill dest");
    }

    /*fn derive_key(&self, password: &str) -> u8 {
        0
    }
    fn hash(&self, msg: &str) -> u8 {
        0
    }

    fn aes_encrypt(&self, plaintext: &str) -> String {
        String::new()
    }
    
    fn aes_decrypt(&self, ciphertext: &str) -> String {
        String::new()
    }*/
}
