{
  system ? builtins.currentSystem or "x86_64-linux",
  inputs ? import ./npins { },
  pkgs ? import inputs.nixpkgs { inherit system; },
  nix-audit-closure ? import ./. { inherit system inputs pkgs; },
}:
let
  inherit (pkgs) mkShell;
in
mkShell {
  inputsFrom = [
    nix-audit-closure
  ];

  env.AWS_LC_SYS_USE_SYSTEM = true;

  packages = with pkgs; [
    clippy
    rust-analyzer
    rustfmt
  ];
}
