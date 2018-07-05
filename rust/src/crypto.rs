extern crate ring;
use self::ring::aead;
use self::ring::digest;
use self::ring::rand::SystemRandom;
use self::ring::rand::SecureRandom;

pub struct Crypto {
    cipher: &'static aead::Algorithm,
    hasher: &'static digest::Algorithm,
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
                cipher: &aead::AES_128_GCM,
                hasher: &digest::SHA256,
                salt,
                nonce,
                key_hash: [0; 32],
                cipher_key: [0; 16],
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
