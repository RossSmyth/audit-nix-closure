# audit-nix-closure

Audits a nix closure for Rust executables, then outputs either json or markdown.

> [!WARNING]
> There are many false positives reported, as all this tool can do is inspect the lockfile and report anything in the lockfile that is in the rustsec db.
> Verify that the program actually uses the dependency as-built before taking any actions. 

> [!NOTE]
> Downloads the rustsec advisory database to `"${XDG_CACHE_HOME:-"$HOME/.cache"}/audit-nix-closure"`

## How to use

`audit-nix-closure /run/current-system`

or

`audit-nix-closure --json /run/current-system`

## Example output

### Markdown

```markdown

## '/nix/store/zh7by46xdmq6hhdwjci5da66g9g8yrhv-helix-term/bin/hx'

### RUSTSEC-2026-0204
title: Invalid pointer dereference in `fmt::Pointer` impl for `Atomic` and `Shared` when the underlying pointer is invalid
package: crossbeam-epoch
date: 2026-07-06
url: https://github.com/crossbeam-rs/crossbeam/pull/1276

### RUSTSEC-2026-0233
title: Crafted archives can cause a use-after-free during deserialization
package: rkyv
date: 2026-05-11
url: https://github.com/rkyv/rkyv/issues/666

### RUSTSEC-2026-0234
title: Insufficient archive validation can cause out-of-bounds reads in archives containing hash tables
package: rkyv
date: 2026-05-11
url: https://github.com/rkyv/rkyv/issues/663

### RUSTSEC-2026-0235
title: Insufficient archive validation can cause out-of-bounds reads in archives containing Rc/Arc
package: rkyv
date: 2026-05-13
url: https://github.com/rkyv/rkyv/issues/670

```

### JSON (prettied via jq)

```json
{
  "/nix/store/zh7by46xdmq6hhdwjci5da66g9g8yrhv-helix-term/bin/hx": [
    {
      "aliases": [],
      "date": "2026-07-06",
      "id": "RUSTSEC-2026-0204",
      "package": "crossbeam-epoch",
      "title": "Invalid pointer dereference in `fmt::Pointer` impl for `Atomic` and `Shared` when the underlying pointer is invalid",
      "url": "https://github.com/crossbeam-rs/crossbeam/pull/1276"
    },
    {
      "aliases": [],
      "date": "2026-05-11",
      "id": "RUSTSEC-2026-0233",
      "package": "rkyv",
      "title": "Crafted archives can cause a use-after-free during deserialization",
      "url": "https://github.com/rkyv/rkyv/issues/666"
    },
    {
      "aliases": [],
      "date": "2026-05-11",
      "id": "RUSTSEC-2026-0234",
      "package": "rkyv",
      "title": "Insufficient archive validation can cause out-of-bounds reads in archives containing hash tables",
      "url": "https://github.com/rkyv/rkyv/issues/663"
    },
    {
      "aliases": [],
      "date": "2026-05-13",
      "id": "RUSTSEC-2026-0235",
      "package": "rkyv",
      "title": "Insufficient archive validation can cause out-of-bounds reads in archives containing Rc/Arc",
      "url": "https://github.com/rkyv/rkyv/issues/670"
    }
  ]
}
```

## TODO

* Improve output
* More configurable
* Audit other things?
