use std::env;

fn main() {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.as_slice() == ["version"] || arguments.as_slice() == ["--version"] {
        println!("snolpkg {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    eprintln!(
        "usage: snolpkg add -b|-s <git-url> <module-name> | del <installed-package> | template <installed-package> --role <role> --output <path>"
    );
    std::process::exit(1);
}
