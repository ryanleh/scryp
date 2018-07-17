use std::fs::File;
use std::io::prelude::*;
use std::str;
use Operation;

pub struct FileHandler<'a> {
    name: &'a str,
    operation: &'a Operation,
    remove: bool,
    content: Vec<u8>,
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
        } 
    }

    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
   
    // TODO: Rename all the things
    fn write(&self, filename: &str, content: &Vec<&[u8]>) {
        let mut buffer = File::create(filename)
            .expect("Error creating file (permissions issue?)");
        for obj in content.iter() {
            buffer.write_all(obj);
        }
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.name),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.name),
        }
    }

    pub fn create_enc(&self, params: &'a [u8], ciphertext: &'a [u8]) {
        let mut enc_content = Vec::new();
        
        // Strip old file name of suffix and add on enc
        let enc_name = self.name.split(".")
            .next()
            .expect("Error parsing filename");
        let filename = format!("{}.enc", enc_name);

        // Push all components to be written
        enc_content.push(self.name.as_bytes());
        enc_content.push(b"/");
        enc_content.push(params);
        enc_content.push(ciphertext);
        self.write(&filename, &enc_content);
    }

    pub fn unpack_enc(&self) -> (&str, &[u8]) {
        let split = self.content.iter()
            .position(|&b| b == b"/"[..][0])
            .unwrap();
        let orig_filename = str::from_utf8(&self.content[..split])
            .expect("Filename failed to parse... tampering");
        // +1 is to not include the actual forward slash
        let content = &self.content[split+1..];
        (orig_filename, content)
    }

    pub fn create_orig(&self, plaintext: &[u8], filename: &str) {
        let mut content = Vec::new();
        content.push(plaintext);
        self.write(filename, &content);
    }
}

