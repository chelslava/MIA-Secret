use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Serve {
        #[arg(long)]
        host: Option<String>,

        #[arg(long)]
        port: Option<u16>,
    },
    Health {
        #[arg(long)]
        port: Option<u16>,
    },
    Init,
    Add {
        path: String,
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        login: Option<String>,
        #[arg(long)]
        password: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "tags", value_delimiter = ',')]
        tags: Vec<String>,
    },
    Get {
        path: String,
    },
    List,
    Update {
        path: String,
        #[arg(long)]
        new_path: Option<String>,
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        login: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "tags", value_delimiter = ',')]
        tags: Option<Vec<String>>,
    },
    Delete {
        path: String,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    Import {
        #[command(subcommand)]
        command: ImportCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    Init {
        #[arg(long)]
        force: bool,
    },
    Show,
    Validate,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommands {
    Create {
        name: String,
        #[arg(long = "scopes", value_delimiter = ',')]
        scopes: Vec<String>,
        #[arg(long)]
        expires_at: Option<i64>,
    },
    List,
    Revoke {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ImportCommands {
    Csv {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, value_enum, default_value = "generic")]
        source: ImportSource,
        #[arg(long, value_enum, default_value = "skip")]
        on_duplicate: DuplicateStrategy,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ImportSource {
    Generic,
    Bitwarden,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DuplicateStrategy {
    Skip,
    Update,
}
