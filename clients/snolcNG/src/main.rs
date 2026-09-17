#[cfg(not(target_os = "android"))]
fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let root = match arguments.as_slice() {
        [flag, root] if flag == "--root" => std::path::PathBuf::from(root),
        _ => {
            eprintln!("usage: snolcNG --root <absolute-client-directory>");
            std::process::exit(1);
        }
    };
    if !root.is_absolute() {
        eprintln!("error: client directory must be absolute");
        std::process::exit(1);
    }
    if let Err(error) = snolc_ng::native_ui::run_desktop(root) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "android")]
fn main() {}
