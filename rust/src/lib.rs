extern crate rpassword;
pub mod crypto;
pub mod file_handler;

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

pub fn run(operation: Operation, remove: bool, filenames: Vec<&str>) {
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    let file_handler = FileHandler::new(filenames, operation, remove);
}
