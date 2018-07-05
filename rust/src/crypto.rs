extern crate ring;

struct Crypto {
    hasher: ring::digest::Algorithm,
    salt: u8,
    key_hash: u8,
    cipher_key: u8,
    mac_key: u8,
    nonce: u8,
    ciper: ring::aead::Algorithm,
}

/*
impl Crypto {
    fn get_random_bytes(&self, n: i32) -> i32 {
        0
    }

    fn derive_key(&self, password: &str) -> u8 {
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
    }
}*/
