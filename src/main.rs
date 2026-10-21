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

use clap::arg;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rustsec::{
    Database,
    advisory::Id,
    binary_scanning::load_deps_from_binary,
    database::Query,
    platforms::{Arch, OS},
    repository,
};
use walkdir::WalkDir;

fn get_args() -> clap::ArgMatches {
    clap::Command::new("audit-nix-closure")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Audit a nix closure for vulnerabilities in Rust executables.")
        .arg(arg!(--json).help("Output JSON rather than markdownish"))
        .arg(
            arg!([store_path])
                .required(true)
                .value_name("STORE_PATH")
                .help("Nix store path to analyze"),
        )
        .get_matches()
}

fn main() {
    let args = get_args();
    let closure = args
        .get_raw("store_path")
        .unwrap()
        .last()
        .expect("Requires the last argument to be a nix store path.");

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

    if args.get_flag("json") {
        let mut json = serde_json::Map::with_capacity(vulns.len());

        for (store_path, vulns) in vulns {
            json.insert(
                store_path.to_string_lossy().into_owned(),
                serde_json::Value::Array(
                    vulns
                        .iter()
                        .map(|vuln| {
                            let mut map = serde_json::Map::new();

                            map.insert(
                                "id".to_string(),
                                serde_json::Value::from(vuln.advisory.id.as_str()),
                            );
                            map.insert(
                                "package".to_string(),
                                serde_json::Value::from(vuln.advisory.package.as_str()),
                            );
                            map.insert(
                                "title".to_string(),
                                serde_json::Value::from(vuln.advisory.title.as_str()),
                            );
                            map.insert(
                                "date".to_string(),
                                serde_json::Value::from(vuln.advisory.date.as_str()),
                            );
                            map.insert(
                                "aliases".to_string(),
                                serde_json::Value::from(
                                    vuln.advisory
                                        .aliases
                                        .iter()
                                        .map(Id::as_str)
                                        .collect::<Vec<_>>(),
                                ),
                            );

                            if let Some(url) = &vuln.advisory.url {
                                map.insert(
                                    "url".to_string(),
                                    serde_json::Value::from(url.as_str()),
                                );
                            }

                            map.into()
                        })
                        .collect(),
                ),
            );
        }

        writeln!(stdout, "{}", serde_json::Value::Object(json).to_string()).unwrap();
    } else {
        writeln!(stdout, "# Rustsec audit of {closure:?}").unwrap();

        for (store_path, vulns) in vulns {
            writeln!(stdout, "## '{}'\n", store_path.to_string_lossy()).unwrap();

            for vuln in vulns {
                writeln!(stdout, "### {}", vuln.advisory.id).unwrap();
                writeln!(stdout, "title: {}", vuln.advisory.title).unwrap();
                writeln!(stdout, "package: {}", vuln.advisory.package).unwrap();
                writeln!(stdout, "date: {}", vuln.advisory.date).unwrap();

                if !vuln.advisory.aliases.is_empty() {
                    writeln!(
                        stdout,
                        "aliases: {}",
                        vuln.advisory
                            .aliases
                            .iter()
                            .map(Id::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .unwrap();
                }

                if let Some(url) = vuln.advisory.url {
                    writeln!(stdout, "url: {}", url).unwrap();
                }
                writeln!(stdout, "").unwrap();
            }
        }
    }
}
