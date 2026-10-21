# audit-nix-closure

Audits a nix closure for Rust executables, then outputs either json or markdown.

> [!NOTE]
> Downloads the rustsec advisory database to "${XDG_CACHE_HOME:-"$HOME/.cache"}/audit-nix-closure"

## How to use

`audit-nix-closure /run/current-system`

## TODO

* Improve output
* More configurable
* Audit other things?
