#[cfg(not(target_os = "android"))]
mod desktop;

#[cfg(not(target_os = "android"))]
fn main() {
    if let Err(error) = desktop::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "android")]
fn main() {}
