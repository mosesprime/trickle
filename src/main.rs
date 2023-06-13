use clap::Parser;

mod cli;
use crate::cli::Cli;
use trickle::{upload_file, download_file};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.debug {
        0 => println!("Debug mode off"),
        _ => println!("Debug mode on"),
    }

    match &cli.command {
        Some(cli::Commands::Upload { path }) => {
            upload_file(path.to_path_buf()).await?
        },
        Some(cli::Commands::Download { path }) => {
            download_file(path.to_path_buf()).await?
        },
        None => {}
    }

   Ok(())
}

 
