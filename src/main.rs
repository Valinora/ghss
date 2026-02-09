mod cli;

use std::process;

use clap::Parser;

use cli::Cli;

fn main() {
    let args = Cli::parse();

    if !args.file.exists() {
        eprintln!("error: file not found: {}", args.file.display());
        process::exit(1);
    }

    println!("Parsing workflow file: {}", args.file.display());
}
