fn main() {
    println!(
        "cargo:rustc-env=SNOLPKG_TARGET={}",
        std::env::var("TARGET").expect("Cargo must set TARGET")
    );
}
