use std::fs::File;
use std::io::prelude::*;
use Operation;


pub struct FileHandler<'a> {
    name: &'a str,
    operation: &'a Operation,
    remove: bool,
    content: Vec<u8>,
    to_write_name: String,
    to_write: Vec<u8>,
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
        File::create(&self.to_write_name)
                    .expect("Error creating file (permissions issue?)")
                    .write(&self.to_write)
                    .expect("Error writing to file (permissions issue?)");
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.name),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.name),
        }
    }
}
