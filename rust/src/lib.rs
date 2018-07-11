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
    // Declaring early since it's borrowed be file_handler
    let mut ciphertext: Vec<u8> = Vec::new();
    let plaintext: &[u8];
    let file_handler = FileHandler::new(filename, &Operation::DECRYPT, remove);

    let (filename, content) = file_handler.unpack_enc();

    // TODO: Do this with split?
    let params = &content[..crypto::PARAMS_LEN];

    // TODO: fix this
    ciphertext[..content.len()-params.len()].copy_from_slice(&content[crypto::PARAMS_LEN..]);
    let crypto = Crypto::from_params(password, params);
    plaintext = crypto.aes_decrypt(&mut ciphertext, filename)
        .expect("Decryption Failed");

    file_handler.create_orig(plaintext, filename);

}

pub fn run(operation: &Operation, remove: bool, filenames: Vec<&str>) {
    //let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    let password = &"test";
    for filename in filenames.iter() {
        let modifier = match operation {
            Operation::DECRYPT => decryptor,
            Operation::ENCRYPT => encryptor,
        };
        modifier(filename, &password, remove);
    }
}
