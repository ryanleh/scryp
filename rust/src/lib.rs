extern crate rpassword;
pub mod crypto;
pub mod file_handler;
use file_handler::FileHandler;
use crypto::Crypto;
use std::process;

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

// TODO: handle remove
fn encryptor(filename: &str, password: &str, remove: bool) {
    let mut ciphertext: Vec<u8> = Vec::new();
    let crypto = Crypto::new(password, None, None);
    let params = crypto.params();
    let file_handler = FileHandler::new(filename, &Operation::ENCRYPT, remove);
    // TODO: Handle Error
    crypto.aes_encrypt(file_handler.content(), &mut ciphertext, filename);

    // Making assumption that ciphertext is always full length of ciphertext buffer
    // (which should be true)
    file_handler.create_enc(&params, &ciphertext);

    // TODO: this will eventually have a guard so if writing file fails 
    // this won't remove original
    if remove {
        file_handler.del_original();
    };
}

fn decryptor(filename: &str, password: &str, remove: bool) -> () {
    let mut ciphertext: Vec<u8>; 
    let plaintext: &[u8];
    let file_handler = FileHandler::new(filename, &Operation::DECRYPT, remove);

    let (filename, content) = file_handler.unpack_enc();
    // Split parameters and ciphertext
    let (params, temp_slice) = content.split_at(crypto::PARAMS_LEN);
    ciphertext = vec![0; temp_slice.len()];
    ciphertext[..temp_slice.len()].copy_from_slice(temp_slice);

    // TODO: This is a timing attack I'm pretty sure
    let crypto = Crypto::from_params(password, params).unwrap_or_else(|e| {
        println!("{}: Password incorrect or file has been tampered with", filename);
        // TODO: This should simply return an error instead of killing the process
        process::exit(1);
    });
    
    plaintext = crypto.aes_decrypt(&mut ciphertext, filename).unwrap_or_else(|e| {
        println!("{}: Decryption failed", filename);
        // TODO: This should simply return an error instead of killing the process
        process::exit(1);
    });

    file_handler.create_orig(plaintext, filename);

    // TODO: this will eventually have a guard so if writing file fails 
    // this won't remove original
    if remove {
        file_handler.del_original();
    };

}

pub fn run(operation: &Operation, remove: bool, filenames: Vec<&str>) {
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    for filename in filenames.iter() {
        let modifier = match operation {
            Operation::DECRYPT => decryptor,
            Operation::ENCRYPT => encryptor,
        };
        modifier(filename, &password, remove);
    }
}
