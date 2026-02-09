mod cli;
mod workflow;

use std::process;

use clap::Parser;

use cli::Cli;

fn main() {
    let args = Cli::parse();

    if !args.file.exists() {
        eprintln!("error: file not found: {}", args.file.display());
        process::exit(1);
    }

    match workflow::parse_workflow(&args.file) {
        Ok(uses_refs) => {
            for uses in &uses_refs {
                println!("{uses}");
            }
        }
        Err(e) => {
            eprintln!("error: failed to parse workflow: {e}");
            process::exit(1);
        }
    }
}
