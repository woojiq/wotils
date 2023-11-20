{
  inputs = {};

  outputs = {
    self,
    nixpkgs,
  }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in {
    packages.${system}.default = pkgs.stdenv.mkDerivation {
      pname = "ping";
      version = "0.1";
      src = ./.;
      nativeBuildInputs = with pkgs; [
        meson
        ninja
        pkg-config
      ];
    };
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        # C lang
        clang-tools
        meson
        ninja
        gdb
        # Network utils for debugging
        tcpdump
        inetutils
      ];
    };
  };
}
