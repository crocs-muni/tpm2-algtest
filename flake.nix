{
  description = "TPM Algtest";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        pythonPackages = with pkgs.python311Packages; [
          venvShellHook

        ];
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = [
            python311
            cmake
            openssl
            tpm2-tools
            tpm2-tss
          ] ++ pythonPackages;

          venvDir = ".virt";
          postVenvCreation = ''
            unset SOURCE_DATE_EPOCH
            pip install --upgrade pip
            pip install wheel
            pip install --requirement requirements.txt
          '';
        };
      }
    );
}
