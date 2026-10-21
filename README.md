# audit-nix-closure

Audits a nix closure for Rust executables, then spews out all their crap to stdout.

> [!NOTE]
> Downloads the rustsec advisory database to "${XDG_CACHE_HOME:-"$HOME/.cache"}/audit-nix-closure"

## How to use

`audit-nix-closure /run/current-system`

## TODO

* Improve output
* More configurable
* Audit other things?
