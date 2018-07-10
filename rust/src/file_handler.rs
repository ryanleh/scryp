use std::fs::File;
use std::io::prelude::*;
use std::str;
use Operation;

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

    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
   
    // TODO: Rename all the things
    fn write(&mut self) {
        let mut buffer = File::create(&self.to_write_name)
            .expect("Error creating file (permissions issue?)");
        for obj in self.to_write.iter() {
            buffer.write_all(obj);
        }
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.name),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.name),
        }
    }

    pub fn create_enc(&mut self, params: &'a [u8], ciphertext: &'a [u8]) {
        let mut enc_name = self.name.split(".")
            .next()
            .expect("Error parsing filename");
        self.to_write_name = format!("{}.enc", enc_name);
        self.to_write.push(self.name.as_bytes());
        self.to_write.push(b"/");
        self.to_write.push(params);
        self.to_write.push(ciphertext);
        self.write();
    }

    // TODO: Perhaps not make this self mutable and handle filename in create?
    pub fn unpack_enc(&mut self) -> (&str, &[u8]) {
        let split = self.content.iter()
            .position(|&b| b == b"/"[..][0])
            .unwrap();
        let orig_filename = str::from_utf8(&self.content[..split])
            .expect("Filename failed to parse... tampering");
        let content = &self.content[split+1..];
        self.to_write_name = orig_filename.to_string();
        (orig_filename, content)
    }

    pub fn create_orig(&mut self, plaintext: &'a [u8]) {
        self.to_write.push(plaintext);
        self.write()
    }
}

