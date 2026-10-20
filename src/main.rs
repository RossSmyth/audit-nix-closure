use std::{
    ffi::{OsStr, OsString},
    io::BufRead,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::PermissionsExt,
    },
    process::Command,
};

use walkdir::WalkDir;

fn main() {
    let Some(closure) = std::env::args_os().skip(1).next() else {
        panic!("No store path to analyze. Must be the only argument.")
    };

    let closure_analysis = Command::new("nix-store").arg("-qR").arg(closure).output();
    let store_paths = match closure_analysis {
        Ok(out) => out.stdout,
        Err(err) => panic!("Failed to get runtime closure:\n{err:?}"),
    };

    let store_paths = OsString::from_vec(store_paths);

    let mut executable_paths = Vec::new();

    for path in store_paths.as_encoded_bytes().split(|&b| b == b'\n') {
        for entry in WalkDir::new(OsStr::from_bytes(path))
            .into_iter()
            .flatten()
            .filter(|entry| entry.file_type().is_file())
        {
            let Ok(meta) = entry.metadata() else { continue };
            let mode = meta.permissions().mode();

            // Only push executable paths. Shared libraries or executables.
            if (mode & 0o111) != 0 {
                executable_paths.push(entry.into_path());
            }
        }
    }
}
