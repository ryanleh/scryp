use std::fs::File;
use std::io::prelude::*;
use Operation;
use crypto::Crypto;

pub struct FileHandler<'a> {
    name: &'a str,
    operation: &'a Operation,
    remove: bool,
    content: Vec<u8>,
    to_write_name: String,
    to_write: Vec<&'a [u8]>,
}

impl<'a> FileHandler<'a> {
    pub fn new(name: &'a str, operation: &'a Operation, remove: bool) -> FileHandler<'a> {
        let mut content = Vec::new();
        File::open(&name)
            .expect("Error opening file")
            .read_to_end(&mut content)
            .expect("Error reading file");
        FileHandler{ name,
                     content, 
                     remove, 
                     operation, 
                     to_write_name: String::new(),
                     to_write: Vec::new(),
        } 
    }

    pub fn write(&self) {
        let mut buffer = File::create(&self.to_write_name)
            .expect("Error creating file (permissions issue?)");
        buffer.write_all(self.name.as_bytes());
        buffer.write_all(b"\\");
        self.to_write.iter()
            .map(|param| buffer.write_all(param));
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.name),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.name),
        }
    }

    fn create_enc(&mut self, crypto: &'a Crypto) {
        crypto.push_params(&mut self.to_write);
    }
}
