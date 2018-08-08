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
        File::open(&name)?
            .read_to_end(&mut content)?;
        Ok(FileHandler{ name,
                        content, 
                        remove, 
                        operation, 
        })
    }

    /// Returns the file's contents
    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
  
    /// Writes content to the specified filename
    // TODO: Perhaps change content name? A bit ambigious
    fn write(&self, filename: &str, content: &Vec<&[u8]>) -> Result<(), ScryptoError> {
        let mut buffer = File::create(filename)?;
        // Content is a vector containing u8 slices so we write each one in order
        for obj in content.iter() {
            buffer.write_all(obj)?;
        }
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.name),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.name),
        }
        // Remove the original file if the -r flag was specified
        if self.remove {
            fs::remove_file(self.name)?; 
        }
        Ok(())
    }

    /// Extracts the filename and concatenates it with crypo params and ciphertext
    pub fn create_enc(&self, mut content: Vec<&'a [u8]>) -> Result<(), ScryptoError> {
        let mut enc_content = Vec::new();
        // Strip old file name of suffix and add on enc
        // TODO: Check this error
        // TODO: I think this will bug out on hidden files?
        let enc_name: &str; 
        // Make exception for hidden files
        if self.name.starts_with(".") {
            enc_name = match self.name[1..].split(".").next() {
                Some(n) => n,
                None => return Err(ScryptoError::IO(io::Error::new(io::ErrorKind::Other, 
                                                                   "Invalid filename format"))),
            }
        } else {
            enc_name = match self.name.split(".").next() {
                Some(n) => n,
                None => return Err(ScryptoError::IO(io::Error::new(io::ErrorKind::Other, 
                                                                   "Invalid filename format"))),
            };
        }
        let filename = format!("{}.enc", enc_name);

        // Push all components to be written
        enc_content.push(self.name.as_bytes());
        enc_content.push(b"/");
        enc_content.append(&mut content);
        self.write(&filename, &enc_content)?;
        Ok(())
    }

    /// Extracts filename and params/ciphertext from enc file
    pub fn unpack_enc(&self) -> Result<(&str, &[u8]), ScryptoError> {
        // Splits the enc file on the / inbetween filename and params/ciphertext
        let split = match self.content.iter().position(|&b| b == b"/"[..][0]) {
            Some(n) => n,
            None => return Err(ScryptoError::Integrity),
        };
        let orig_filename = str::from_utf8(&self.content[..split])
            .map_err(|_e| ScryptoError::Integrity)?;        
        // +1 is to not include the actual forward slash
        let crypto_content = &self.content[split+1..];
        Ok((orig_filename, crypto_content))
    }

    /// Writes the plaintext to given filename
    pub fn create_orig(&self, plaintext: &[u8], filename: &str) -> Result<(), ScryptoError> {
        let mut content = Vec::new();
        content.push(plaintext);
        self.write(filename, &content)?;
        Ok(())
    }
}

