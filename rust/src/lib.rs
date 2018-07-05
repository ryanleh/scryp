pub mod crypto;
pub mod file_handler;

pub enum Operation {
    DECRYPT,
    ENCRYPT,
}

pub fn run(operation: Operation, remove: bool, filenames: Vec<&str>) {
    
}
