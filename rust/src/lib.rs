extern crate rpassword;
pub mod crypto;
pub mod file_handler;
use file_handler::FileHandler;

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

fn encryptor(file_handler: FileHandler, password: &str) {
}

fn decryptor(file_handler: FileHandler, password: &str) {
}

pub fn run(operation: &Operation, remove: bool, filenames: Vec<&str>) {
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    for filename in filenames.iter() {
        let file_handler = FileHandler::new(filename, &operation, remove);
        let modifier = match operation {
            Operation::DECRYPT => decryptor,
            Operation::ENCRYPT => encryptor,
        };
        modifier(file_handler, &password);
    }
}
