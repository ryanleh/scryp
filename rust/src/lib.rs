extern crate rpassword;
extern crate ring;
extern crate rayon;
pub mod crypto;
pub mod file_handler;
use rayon::prelude::*;
use file_handler::FileHandler;
use crypto::{ Crypto };
use std::fmt;
use std::io;

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

#[derive(Debug)]
pub enum ScryptoError {
    Password,
    Integrity,
    Runtime,
    IO(io::Error),
}

impl From<ring::error::Unspecified> for ScryptoError {
    fn from(_: ring::error::Unspecified) -> Self { ScryptoError::Runtime }
}

impl From<io::Error> for ScryptoError {
    fn from(err: io::Error) -> Self { ScryptoError::IO(err)}
}

impl fmt::Display for ScryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScryptoError::Password => write!(f, "Incorrect password or file tampered with"),
            ScryptoError::Integrity => write!(f, "File has been tampered with"),
            ScryptoError::Runtime => write!(f, "Runtime error occured"),
            ScryptoError::IO(ref err) => write!(f, "IO error occured: {}", err)
        }
    }
}

/// Handles file_handler and crypto operations for generating enc file
fn encryptor(filepath: &str, 
             output_dir: &str,
             password: &str,
             remove: bool) -> Result<(), ScryptoError> {
    let mut ciphertext: Vec<u8> = Vec::new();
    let crypto = Crypto::new(password, None, None)?;
    let file_handler = FileHandler::new(filepath, output_dir, &Operation::ENCRYPT, remove)?;
    crypto.aes_encrypt(file_handler.get_content(),
        &mut ciphertext, 
        file_handler.get_filename())?;

    let crypto_content = crypto.pack_enc(&ciphertext);
    // Invariant: ciphertext takes up entire length of ciphertext vector
    file_handler.create_enc(crypto_content)?;
    Ok(())
}

/// Handles file_handler and crypto operations for decrypting enc file
fn decryptor(filepath: &str,
             output_dir: &str, 
             password: &str, 
             remove: bool) -> Result<(), ScryptoError> {
    let file_handler = FileHandler::new(filepath, output_dir, &Operation::DECRYPT, remove)?;
    let (orig_filename, crypto_content) = file_handler.dismantle_enc()?;
    let (mut ciphertext, crypto) = Crypto::unpack_enc(password, crypto_content)?;
    
    let plaintext: &[u8];
    plaintext = crypto.aes_decrypt(&mut ciphertext, orig_filename)?;
    file_handler.create_orig(plaintext)?;
    Ok(())
}

pub fn run(operation: &Operation, remove: bool, filepaths: Vec<&str>, output_dir: &str) {
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    filepaths.into_par_iter()
        .for_each(|filepath| {
            match operation {
                Operation::DECRYPT => {
                    decryptor(filepath, output_dir, &password, remove).unwrap_or_else(|err| {
                        println!("Decrypting {} failed: {}", filepath, err);
                    });
                },
                Operation::ENCRYPT => {
                    encryptor(filepath, output_dir, &password, remove).unwrap_or_else(|err| {
                        println!("Encrypting {} failed: {}", filepath, err);
                    });
                }
            };
        });
}
