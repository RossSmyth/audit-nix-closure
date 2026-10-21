# audit-nix-closure

Audits a nix closure for Rust executables, then spews out all their crap to stdout.

> [!NOTE]
> Currently unconditionally downloads the rustsec advisory db to CARGO_HOME.

## How to use

`audit-nix-closure /run/current-system`

## TODO

* Improve output
* More configurable
