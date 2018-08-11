use self::io::prelude::*;
use std::fs::File;
use std::io;
use std::fs;
use std::path::Path;
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
        // TODO: Test empty
        // Strip filename of any path - encrypt to current directory by default
        let stripped_name = Path::new(name)
            .file_name().unwrap()
            .to_str().unwrap();
        Ok(FileHandler{ name: stripped_name,
                        content, 
                        remove, 
                        operation, 
        })
    }

    /// Returns the file's name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the file's contents
    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
  
    /// Writes to_write to the specified filename
    fn write(&self, filename: &str, to_write: &Vec<&[u8]>) -> Result<(), ScryptoError> {
        let mut buffer = File::create(filename)?;
        // Content is a vector containing u8 slices so we write each one in order
        for obj in to_write.iter() {
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
        let filename = format!("{}.enc", Path::new(self.name)
            .file_stem().unwrap()
            .to_str().unwrap());

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

