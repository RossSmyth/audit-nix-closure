{
  system ? builtins.currentSystem or "x86_64-linux",
  inputs ? import ./npins { },
  pkgs ? import inputs.nixpkgs { inherit system; },
}:
let
  inherit (pkgs)
    rustPlatform
    lib
    pkg-config
    aws-lc
    ;
in
rustPlatform.buildRustPackage {
  pname = "audit-nix-closure";
  version = "0.2.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    aws-lc
  ];

  env.AWS_LC_SYS_USE_SYSTEM = true;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    license = lib.licenses.blueOak100;
    mainProgram = "audit-nix-closure";
  };
}
