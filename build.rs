use std::{fs::OpenOptions, io::Read, path::Path};

fn main() {
    // Link Shell32.lib for SHChangeNotify
    println!("cargo:rustc-link-lib=shell32");

    // Reload changes from secret file
    println!("cargo:rerun-if-changed=USER_PREF_SECRET");

    // Load USER_PREF_SECRET from environment
    if let Ok(secret) = std::env::var("USER_PREF_SECRET") {
        println!("cargo:rustc-env=USER_PREF_SECRET={}", secret);
    }
    // Load USER_PREF_SECRET from secret file
    else {
        let secret_path =
            Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("USER_PREF_SECRET");
        let mut secret = String::new();
        if let Ok(mut file) = OpenOptions::new().read(true).open(&secret_path) {
            file.read_to_string(&mut secret).unwrap();
        }
        println!("cargo:rustc-env=USER_PREF_SECRET={}", secret);
    }
}
