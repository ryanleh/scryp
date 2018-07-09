extern crate rpassword;
pub mod crypto;
pub mod file_handler;
use file_handler::FileHandler;
use crypto::Crypto;

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

fn encryptor(filename: &str, password: &str, remove: bool) {
    let mut buffer: Vec<u8> = Vec::new();
    let ciphertext: &[u8]; 
    let crypto = Crypto::new(password, None, None);
    let params = crypto.params();
    let mut file_handler = FileHandler::new(filename, &Operation::ENCRYPT, remove);

    {
    let plaintext: &Vec<u8> = file_handler.content();
    // TODO: Handle Error
    ciphertext = crypto.aes_encrypt(plaintext, &mut buffer).unwrap();
    }

    file_handler.create_enc(&params, ciphertext);
}

fn decryptor(filename: &str, password: &str, remove: bool) {
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
