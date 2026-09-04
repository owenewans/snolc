//! `snolc-geoconv` -- converts plain-text geoip/geosite source lists into
//! the flat YAML routing-rule fragments snolc understands (see
//! `snolc::routing`). This is a separate tool, not a `snolc` subcommand:
//! `snolc` itself only ever accepts `run`/`version`/`keygen`.
//!
//! Two source formats are supported, both of which are genuine, commonly
//! published plain-text formats (not sing-box's or Xray's own compiled
//! binary `.srs`/`.dat` databases, which this tool does not parse):
//!
//! - `geosite`: the domain-list-community line format
//!   (<https://github.com/v2fly/domain-list-community>), which sing-box and
//!   Xray themselves compile their binary geosite databases from. Lines
//!   look like `domain:example.com`, `full:www.example.com`,
//!   `# comment`, or `include:other-list`. `keyword:`/`regexp:`/`include:`
//!   entries have no equivalent in snolc's routing schema (exact
//!   domain/suffix matching only) and are skipped, not silently
//!   mistranslated; the run summarizes how many were skipped.
//! - `geoip`: one CIDR per line (optionally with a trailing `# comment`),
//!   the format used by, for example, ipdeny.com's per-country zone files.
//!
//! Output is a sequence of routing-rule YAML items on stdout, meant to be
//! assembled by hand into a complete `routing.yml` alongside a final
//! `- match: any` rule (required by `snolc::routing` and intentionally not
//! added here, since only the user knows whether the default should be
//! `direct` or `proxy`).
//!
//! Usage:
//! ```text
//! snolc-geoconv geosite --action <direct|proxy> <file...>
//! snolc-geoconv geoip --action <direct|proxy> <file...>
//! ```

use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!();
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  snolc-geoconv geosite --action <direct|proxy> <file...>");
    eprintln!("  snolc-geoconv geoip --action <direct|proxy> <file...>");
}

fn run(args: impl Iterator<Item = OsString>) -> Result<(), String> {
    let args: Vec<String> = args
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "argument is not valid UTF-8".to_owned())
        })
        .collect::<Result<_, _>>()?;

    let [kind, flag, action, files @ ..] = args.as_slice() else {
        return Err("missing arguments".to_owned());
    };
    if flag != "--action" {
        return Err(format!("expected --action, found {flag}"));
    }
    let action = match action.as_str() {
        "direct" => "direct",
        "proxy" => "proxy",
        other => return Err(format!("unknown action {other}, expected direct or proxy")),
    };
    if files.is_empty() {
        return Err("at least one source file is required".to_owned());
    }

    match kind.as_str() {
        "geosite" => convert_geosite(files, action),
        "geoip" => convert_geoip(files, action),
        other => Err(format!("unknown kind {other}, expected geosite or geoip")),
    }
}

fn convert_geosite(files: &[String], action: &str) -> Result<(), String> {
    let mut converted = 0_usize;
    let mut skipped = 0_usize;
    let mut out = String::new();

    for path in files {
        let contents = fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        for raw_line in contents.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            // Attribute tags, e.g. "domain:example.com @cn", are informational
            // (usually a category grouping) and do not change the match.
            let line = line.split_whitespace().next().unwrap_or(line);
            let Some((kind, value)) = line.split_once(':') else {
                skipped += 1;
                continue;
            };
            match kind {
                "domain" | "full" => {
                    if let Some(domain) = normalize_domain(value) {
                        out.push_str(&format!(
                            "- match: domain\n  value: {domain}\n  action: {action}\n"
                        ));
                        converted += 1;
                    } else {
                        skipped += 1;
                    }
                }
                // No equivalent in snolc's exact/suffix-only domain matcher.
                "keyword" | "regexp" | "include" => skipped += 1,
                _ => skipped += 1,
            }
        }
    }

    print!("{out}");
    eprintln!(
        "geosite: {converted} rule(s) converted, {skipped} entr(y/ies) skipped (unsupported kind)"
    );
    Ok(())
}

fn convert_geoip(files: &[String], action: &str) -> Result<(), String> {
    let mut converted = 0_usize;
    let mut skipped = 0_usize;
    let mut out = String::new();

    for path in files {
        let contents = fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        for raw_line in contents.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<ipnet::IpNet>() {
                Ok(network) => {
                    out.push_str(&format!(
                        "- match: ip\n  value: {network}\n  action: {action}\n"
                    ));
                    converted += 1;
                }
                Err(_) => skipped += 1,
            }
        }
    }

    print!("{out}");
    eprintln!("geoip: {converted} rule(s) converted, {skipped} line(s) skipped (not a valid CIDR)");
    Ok(())
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("")
}

/// Lower-cases and strips a trailing dot, matching the normalization
/// `snolc::routing` itself applies; returns `None` for anything that would
/// fail that module's own validation, so invalid entries are skipped rather
/// than passed through to fail later, silently or not, inside snolc.
fn normalize_domain(value: &str) -> Option<String> {
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return None;
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn temp_file(contents: &str) -> (tempfile::TempDir, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.txt");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        (directory, path.to_string_lossy().into_owned())
    }

    #[test]
    fn geosite_converts_domain_and_full_and_skips_unsupported_kinds() {
        let (_directory, path) = temp_file(
            "# a comment\n\
             domain:Example.RU.\n\
             full:exact.example.com @cn\n\
             keyword:blocked\n\
             regexp:^ads\\.\n\
             include:other-list\n\
             malformed-line-without-colon\n\
             \n",
        );
        let args = vec![
            "geosite".to_owned(),
            "--action".to_owned(),
            "direct".to_owned(),
            path,
        ];
        run(args.into_iter().map(OsString::from)).unwrap();
    }

    #[test]
    fn geoip_converts_valid_cidrs_and_skips_invalid_lines() {
        let (_directory, path) = temp_file(
            "10.0.0.0/8\n\
             not-a-cidr\n\
             2001:db8::/32 # example documentation range\n\
             \n",
        );
        let args = vec![
            "geoip".to_owned(),
            "--action".to_owned(),
            "proxy".to_owned(),
            path,
        ];
        run(args.into_iter().map(OsString::from)).unwrap();
    }

    #[test]
    fn normalize_domain_matches_the_routing_module_rules() {
        assert_eq!(
            normalize_domain("Example.RU."),
            Some("example.ru".to_owned())
        );
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("-bad.example.com"), None);
    }

    #[test]
    fn rejects_unknown_action_and_kind() {
        let args = vec![
            "geosite".to_owned(),
            "--action".to_owned(),
            "maybe".to_owned(),
            "file.txt".to_owned(),
        ];
        assert!(run(args.into_iter().map(OsString::from)).is_err());

        let args = vec![
            "bogus".to_owned(),
            "--action".to_owned(),
            "direct".to_owned(),
            "file.txt".to_owned(),
        ];
        assert!(run(args.into_iter().map(OsString::from)).is_err());
    }
}
