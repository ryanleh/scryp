extern crate scrypto;
extern crate clap;
use std::path::PathBuf;
use std::fs::canonicalize;
use std::process;
use clap::{Arg, App};
use scrypto::{Operation, run};

fn main() {
    let matches = App::new("scrypto")
        .author("Ryan Lehmkuhl <ryanleh.ob@gmail.com>")
        .version("1.0")
        .about("Encrypt files using 128-bit AES-GCM")
        .arg(Arg::with_name("filepaths")
             .help("Files to encrypt/decrypt (Default is encrypt)")
             .required(true)
             .multiple(true))
        .arg(Arg::with_name("output_dir")
             .help("Directory to output files")
             .short("o")
             .long("output-dir")
             .takes_value(true))
        .arg(Arg::with_name("decrypt")
             .help("Decrypt file")
             .short("d")
             .long("decrypt"))
        .arg(Arg::with_name("remove")
             .help("Remove original file")
             .short("r")
             .long("remove"))
        .get_matches();

    // Collect and canonicalize filepaths
    let rel_filepaths: Vec<&str> = matches.values_of("filepaths").unwrap().collect();
    let mut filepaths: Vec<PathBuf> = Vec::new();
    for filepath in rel_filepaths.iter() {
        match canonicalize(filepath) {
            Err(_e) => {
                println!("{}: file does not exist or is a directory", filepath);
                process::exit(1);
            },
            Ok(filepath) => filepaths.push(filepath),
        }
    } 
    // Remove any duplicate filepaths
    filepaths.sort();
    filepaths.dedup();

    // If user has specified an output directory, make sure it's valid or use 
    // the working directory
    let mut output_dir = PathBuf::new();
    if matches.is_present("output_dir") {
        output_dir.push(matches.value_of("output_dir").unwrap());
        if !output_dir.is_dir() {
            println!("Insufficient privileges or output directory is invalid");
            process::exit(1);
        }
    } else {
        output_dir = std::env::current_dir().unwrap_or_else(|_e| {
            println!("Insufficient privileges or working directory is invalid");
            process::exit(1);
        })
    }

    let operation: Operation;
    if matches.is_present("decrypt") {
        operation = Operation::DECRYPT;
    } else {
        operation = Operation::ENCRYPT;
    }

    let remove: bool;
    if matches.is_present("remove") {
        remove = true;
    } else {
        remove = false;
    }

    run(&operation, remove, filepaths, output_dir.to_str().unwrap());
}
