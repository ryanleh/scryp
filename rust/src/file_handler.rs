use self::io::prelude::*;
use std::fs::File;
use std::io;
use std::fs;
use std::path::Path;
use std::str;
use std::cell::RefCell;
use Operation;
use ScryptoError;

pub struct FileHandler<'a> {
    filename: &'a str,
    filepath: &'a str,
    name_to_write: RefCell<String>,
    content: Vec<u8>,
    operation: &'a Operation,
    remove: bool,
}

impl<'a> FileHandler<'a> {
    pub fn new(filepath: &'a str, 
               operation: &'a Operation, 
               remove: bool) -> Result<FileHandler<'a>, ScryptoError> {
        let mut content = Vec::new();
        File::open(filepath)?
            .read_to_end(&mut content)?;
        // Strip filename of any path - encrypt/decrypt to current directory by default
        let filename = Path::new(filepath)
            .file_name().unwrap()
            .to_str().unwrap();
        Ok(FileHandler{ filename,
                        filepath,
                        name_to_write: RefCell::new(String::new()),
                        content, 
                        operation, 
                        remove, 
        })
    }

    /// Returns the file's name
    pub fn get_filename(&self) -> &str {
        &self.filename
    }

    /// Returns the file's contents
    pub fn get_content(&self) -> &Vec<u8> {
        &self.content
    }
  
    /// Writes to_write to the specified filename
    fn write(&self, to_write: &Vec<&[u8]>) -> Result<(), ScryptoError> {
        let mut buffer = File::create(self.name_to_write.borrow().as_str())?;
        // Content is a vector containing u8 slices so we write each one in order
        for obj in to_write.iter() {
            buffer.write_all(obj)?;
        }
        match self.operation {
            Operation::DECRYPT => println!("File: {} decrypted!", self.filename),
            Operation::ENCRYPT => println!("File: {} encrypted!", self.filename),
        }
        // Remove the original file if the -r flag was specified
        if self.remove {
            fs::remove_file(self.filepath)?; 
        }
        Ok(())
    }

    /// Extracts the filename and concatenates it with crypto_content
    pub fn create_enc(&self, mut crypto_content: Vec<&'a [u8]>) -> Result<(), ScryptoError> {
        let mut to_write: Vec<&[u8]> = Vec::new();
        // Strip old file name of suffix and add on enc
        self.name_to_write.replace(format!("{}.enc", Path::new(self.filename)
            .file_stem().unwrap()
            .to_str().unwrap()));

        // Push all components to be written
        to_write.push(self.filename.as_bytes());
        to_write.push(b"/");
        to_write.append(&mut crypto_content);
        self.write(&to_write)?;
        Ok(())
    }

    /// Extracts filename and crypto_content from enc file
    pub fn dismantle_enc(&self) -> Result<(&str, &[u8]), ScryptoError> {
        // Splits the enc file on the / inbetween filename and params/ciphertext
        let split = match self.content.iter().position(|&b| b == b"/"[..][0]) {
            Some(n) => n,
            None => return Err(ScryptoError::Integrity),
        };
        let orig_filename = str::from_utf8(&self.content[..split])
            .map_err(|_e| ScryptoError::Integrity)?;        
        self.name_to_write.replace(orig_filename.to_string());
        // +1 is to not include the actual forward slash
        let crypto_content = &self.content[split+1..];
        Ok((orig_filename, crypto_content))
    }

    /// Writes the plaintext to given filename
    pub fn create_orig(&self, plaintext: &[u8])-> Result<(), ScryptoError> {
        let mut to_write = Vec::new();
        to_write.push(plaintext);
        self.write(&to_write)?;
        Ok(())
    }
}

