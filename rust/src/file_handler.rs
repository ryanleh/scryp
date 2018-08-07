use std::fs::File;
use std::io;
use self::io::prelude::*;
use std::fs;
use std::str;
use Operation;
use ScryptoError;

pub struct FileHandler<'a> {
    name: &'a str,
    operation: &'a Operation,
    remove: bool,
    content: Vec<u8>,
}

impl<'a> FileHandler<'a> {
    pub fn new(name: &'a str, 
               operation: &'a Operation, 
               remove: bool) -> Result<FileHandler<'a>, ScryptoError> {
        let mut content = Vec::new();
        // TODO: Test this - perhaps use and_then?
        File::open(&name)?
            .read_to_end(&mut content)?;
        Ok(FileHandler{ name,
                        content, 
                        remove, 
                        operation, 
        })
    }

    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
   
    fn write(&self, filename: &str, content: &Vec<&[u8]>) -> Result<(), ScryptoError> {
        // TODO: Test throwing all these errors
        let mut buffer = File::create(filename)?;
        for obj in content.iter() {
            buffer.write_all(obj)?;
        }
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.name),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.name),
        }
        if self.remove {
            fs::remove_file(self.name)?; 
        }
        Ok(())
    }

    pub fn create_enc(&self, params: &'a [u8], ciphertext: &'a [u8]) -> Result<(), ScryptoError> {
        let mut enc_content = Vec::new();
        // Strip old file name of suffix and add on enc
        // TODO: Check this error
        // TODO: I think this will bug out on hidden files?
        let enc_name = match self.name.split(".").next() {
            Some(n) => n,
            None => return Err(ScryptoError::IO(io::Error::new(io::ErrorKind::Other, 
                                                               "Invalid filename format"))),
        };
        let filename = format!("{}.enc", enc_name);

        // Push all components to be written
        enc_content.push(self.name.as_bytes());
        enc_content.push(b"/");
        enc_content.push(params);
        enc_content.push(ciphertext);
        self.write(&filename, &enc_content)?;
        Ok(())
    }

    pub fn unpack_enc(&self) -> Result<(&str, &[u8]), ScryptoError> {
        let split = match self.content.iter().position(|&b| b == b"/"[..][0]) {
            Some(n) => n,
            None => return Err(ScryptoError::Integrity),
        };
        // TODO: Test this
        let orig_filename = str::from_utf8(&self.content[..split])
            .map_err(|_e| ScryptoError::Integrity)?;        
        
        // +1 is to not include the actual forward slash
        let crypto_content = &self.content[split+1..];
        Ok((orig_filename, crypto_content))
    }

    pub fn create_orig(&self, plaintext: &[u8], filename: &str) -> Result<(), ScryptoError> {
        let mut content = Vec::new();
        content.push(plaintext);
        self.write(filename, &content)?;
        Ok(())
    }
}

