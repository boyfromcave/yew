//! See Cargo.toml: there is no home directory in a browser; the parameters arrive as bytes.
pub fn home_dir() -> Option<std::path::PathBuf> {
    None
}
