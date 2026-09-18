use std::env;
use std::fs;
use std::path::Path;

use snolc_ng::{AccessProvisioning, ProvisionProfile};

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    let [socket, instance, profile, user_id, client_id, seq] = arguments.as_slice() else {
        return Err(
            "usage: panel <socket> <policy-instance> <profile.toml> <user-id> <client-id> <seq>"
                .into(),
        );
    };
    let profile = fs::read_to_string(profile).map_err(|error| error.to_string())?;
    let profile = ProvisionProfile::parse_toml(&profile).map_err(|error| error.to_string())?;
    let seq = seq
        .parse::<u64>()
        .map_err(|_| "seq must be an unsigned integer".to_owned())?;
    let provisioning = AccessProvisioning::new(profile, user_id, client_id, seq)
        .map_err(|error| error.to_string())?;
    let response =
        snolc::control::request(Path::new(socket), instance, provisioning.request(), 16_384)
            .map_err(|error| error.to_string())?;
    let access = provisioning
        .finish(&response)
        .map_err(|error| error.to_string())?;
    println!("{}", access.uri);
    Ok(())
}
