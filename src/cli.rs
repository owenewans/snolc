use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{Error, Result};

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Run(PathBuf),
    Version,
    Keygen,
}

pub fn parse<I>(args: I) -> Result<Command>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let command = args
        .next()
        .ok_or_else(|| Error::Usage("missing command".to_owned()))?;

    match command.to_str() {
        Some("run") => {
            let path = args
                .next()
                .ok_or_else(|| Error::Usage("run requires a configuration path".to_owned()))?;
            reject_extra(args)?;
            if path.is_empty() {
                return Err(Error::Usage("configuration path is empty".to_owned()));
            }
            Ok(Command::Run(PathBuf::from(path)))
        }
        Some("version") => {
            reject_extra(args)?;
            Ok(Command::Version)
        }
        Some("keygen") => {
            reject_extra(args)?;
            Ok(Command::Keygen)
        }
        Some(_) => Err(Error::Usage("unknown command".to_owned())),
        None => Err(Error::Usage("command is not valid UTF-8".to_owned())),
    }
}

fn reject_extra(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    if args.next().is_some() {
        return Err(Error::Usage("unexpected argument".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_only_the_public_commands() {
        assert_eq!(
            parse(args(&["run", "client.yml"])).unwrap(),
            Command::Run(PathBuf::from("client.yml"))
        );
        assert_eq!(parse(args(&["version"])).unwrap(), Command::Version);
        assert_eq!(parse(args(&["keygen"])).unwrap(), Command::Keygen);
    }

    #[test]
    fn rejects_flags_and_extra_arguments() {
        assert!(parse(args(&["run", "--config", "client.yml"])).is_err());
        assert!(parse(args(&["version", "verbose"])).is_err());
        assert!(parse(args(&["serve"])).is_err());
        assert!(parse(args(&[])).is_err());
    }
}
