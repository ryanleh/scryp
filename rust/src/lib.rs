extern crate rpassword;
pub mod crypto;
pub mod file_handler;
use file_handler::FileHandler;
use crypto::{ CryptoError, Crypto };

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

fn encryptor(filename: &str, password: &str, remove: bool) -> Result<(), CryptoError>{
    let mut ciphertext: Vec<u8> = Vec::new();
    // TODO: Handle Error
    let crypto = Crypto::new(password, None, None)?;
    let params = crypto.params();
    let file_handler = FileHandler::new(filename, &Operation::ENCRYPT, remove);
    crypto.aes_encrypt(file_handler.content(), &mut ciphertext, filename)?;

    // Making assumption that ciphertext is always full length of ciphertext buffer
    // (which should be true)
    file_handler.create_enc(&params, &ciphertext);
    Ok(())
}

fn decryptor(filename: &str, password: &str, remove: bool) -> Result<(), CryptoError> {
    let file_handler = FileHandler::new(filename, &Operation::DECRYPT, remove);
    let (filename, content) = file_handler.unpack_enc();
    let (mut ciphertext, crypto) = Crypto::unpack_enc(password, content)?;
    
    let plaintext: &[u8];
    plaintext = crypto.aes_decrypt(&mut ciphertext, filename)?;
    file_handler.create_orig(plaintext, filename);
    Ok(())
}

pub fn run(operation: &Operation, remove: bool, filenames: Vec<&str>) {
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    for filename in filenames.iter() {
        match operation {
            Operation::DECRYPT => {
                decryptor(filename, &password, remove).unwrap_or_else(|err| {
                    println!("Decrypting {} failed: {}", filename, err);
                });
            },
            Operation::ENCRYPT => {
                encryptor(filename, &password, remove).unwrap_or_else(|err| {
                    println!("Encrypting {} failed: {}", filename, err);
                });
            }
        };
    }
}
