use std::io::{self, Write};
use std::process::ExitCode;

use snolc::cli::{self, Command};
use snolc::error::{Error, Result};
use snolc::identity::Identity;
use snolc::logging::{Level, Logger};

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("error 99");
    }));

    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err((error, logger)) => {
            logger.record(Level::Error, &error.to_string());
            eprintln!("error {}", error.code());
            ExitCode::from(error.code())
        }
    }
}

fn execute() -> std::result::Result<(), (Error, Logger)> {
    let logger = Logger::from_env().map_err(|error| (error, Logger::disabled()))?;
    let command =
        cli::parse(std::env::args_os().skip(1)).map_err(|error| (error, logger.clone()))?;

    let result = match command {
        Command::Version => write_stdout(&format!(
            "commit {}\nwire {}\n",
            snolc::COMMIT_VERSION,
            snolc::WIRE_VERSION
        )),
        Command::Keygen => {
            let identity =
                Identity::generate().map_err(|error| Error::Authentication(error.to_string()));
            identity.and_then(|identity| write_stdout(&identity.yaml()))
        }
        Command::Run(path) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(Error::from);
            runtime.and_then(|runtime| runtime.block_on(snolc::runtime::run(&path, logger.clone())))
        }
    };

    result.map_err(|error| (error, logger))
}

fn write_stdout(value: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(value.as_bytes())?;
    stdout.flush()?;
    Ok(())
}
