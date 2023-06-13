use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// download
    Download {
        /// specify the path to download to
        #[arg(short, long)]
        path: PathBuf,
    },
    /// upload
    Upload {
        /// specify the path to upload from
        #[arg(short, long)]
        path: PathBuf,
    },
}
