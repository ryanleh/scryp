extern crate scrypto;
extern crate clap;
use std::path;
use std::process;
use clap::{Arg, App};
use scrypto::{Operation, run};

fn main() {
    let matches = App::new("scrypto")
        .author("Ryan Lehmkuhl <ryanleh.ob@gmail.com>")
        .version("1.0")
        .about("Encrypt files using 128-bit AES-GCM")
        .arg(Arg::with_name("filenames")
             .help("Files to encrypt/decrypt (Default is encrypt)")
             .required(true)
             .multiple(true))
        .arg(Arg::with_name("output_dir")
             .help("Directory to output files")
             .short("o")
             .long("output-dir"))
        .arg(Arg::with_name("decrypt")
             .help("Decrypt file")
             .short("d")
             .long("decrypt"))
        .arg(Arg::with_name("remove")
             .help("Remove original file")
             .short("r")
             .long("remove"))
        .get_matches();

    let filenames: Vec<&str> = matches.values_of("filenames").unwrap().collect();

    let mut output_dir = path::PathBuf::new();
    if matches.is_present("output_dir") {
        output_dir.push(matches.value_of("output_dir").unwrap());
        if !output_dir.is_dir() {
            println!("Insufficient privleges or working directory is invalid");
            process::exit(1);
        }
    } else {
        output_dir = std::env::current_dir().unwrap_or_else(|_e| {
            println!("Insufficient privleges or working directory is invalid");
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

    run(&operation, remove, filenames, output_dir.to_str().unwrap());
}
