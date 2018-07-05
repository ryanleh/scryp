use std::fs::File;
use std::io::prelude::*;
use Operation;


struct FileHandler {
    content: Vec<u8>,
    operation: Operation,
    name: String,
    to_write_name: String,
    to_write: Vec<u8>,
}

impl FileHandler {
    fn new(name: String, operation: Operation) -> FileHandler {
        let mut content = Vec::new();
        File::open(&name)
            .expect("Error opening file")
            .read_to_end(&mut content);
        FileHandler{ content, 
                     name, 
                     operation, 
                     to_write_name: String::new(),
                     to_write: Vec::new(),
        } 
    }

    fn write(&self) {
        File::create(&self.to_write_name)
                    .expect("Error creating file (permissions issue?)")
                    .write(&self.to_write);
        match self.operation {
            ref DECRYPT => println!("File: {} decrypted!", self.name),
            ref ENCRYPT => println!("File: {} encrypted!", self.name),
        }
    }
}
