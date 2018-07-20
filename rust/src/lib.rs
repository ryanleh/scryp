extern crate rpassword;
pub mod crypto;
pub mod file_handler;
use file_handler::FileHandler;
use crypto::Crypto;

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
}

fn decryptor(filename: &str, password: &str, remove: bool) {
    let mut ciphertext: Vec<u8>; 
    let plaintext: &[u8];
    let file_handler = FileHandler::new(filename, &Operation::DECRYPT, remove);

    let (filename, content) = file_handler.unpack_enc();

    let (params, temp_slice) = content.split_at(crypto::PARAMS_LEN);
    ciphertext = vec![0; temp_slice.len()];
    ciphertext[..temp_slice.len()].copy_from_slice(temp_slice);

    let crypto = Crypto::from_params(password, params)
        .expect("Failed to parse crypto params");
    plaintext = crypto.aes_decrypt(&mut ciphertext, filename)
        .expect("Decryption Failed");

    file_handler.create_orig(plaintext, filename);
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
