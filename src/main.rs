use std::{
    ffi::{OsStr, OsString},
    io::Write,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::PermissionsExt,
    },
    process::Command,
    time::Duration,
};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rustsec::{
    Database,
    binary_scanning::load_deps_from_binary,
    database::Query,
    platforms::{Arch, OS},
    repository,
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

    let cache_dir = dirs::cache_dir()
        .expect("Unable to find cache dir, usually at XDG_CACHE_HOME or something")
        .join("audit-nix-closure");

    let repo = repository::git::Repository::fetch(
        repository::git::DEFAULT_URL,
        cache_dir,
        true,
        Duration::from_secs(10),
    )
    .expect("Unable to get vulnerability db");

    let vuln_db = Database::load_from_repo(&repo).unwrap();

    let query = Query::crate_scope()
        .target_arch(vec![Arch::X86_64])
        .target_os(vec![OS::Linux]);

    let vulns: Vec<_> = executable_paths
        .par_iter()
        .map(|path| {
            let path = path.as_path();
            let contents = std::fs::read(path).unwrap();

            let lock_file = match load_deps_from_binary(&contents, Some(usize::MAX)) {
                Ok((_, rustsec::binary_scanning::BinaryReport::Complete(report))) => report,
                _ => return None,
            };

            Some((path, vuln_db.query_vulnerabilities(&lock_file, &query)))
        })
        .flatten()
        .filter(|(_, vulns)| !vulns.is_empty())
        .collect();

    let mut stdout = std::io::stdout().lock();

    for (store_path, vulns) in vulns {
        vulns.into_iter().for_each(|vuln| {
            writeln!(
                stdout,
                r#"""{store_path:?}, "{}", "{}", "{}""""#,
                vuln.package.name.as_str(),
                vuln.advisory.id.as_str(),
                vuln.advisory.title.as_str(),
            )
            .unwrap();
        });
    }
}
