fn main() {
    // Link Shell32.lib for SHChangeNotify
    println!("cargo:rustc-link-lib=shell32");
}
