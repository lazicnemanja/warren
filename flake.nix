{
  description = "warren - OpenVPN profile manager: many tunnels at once, encrypted saved passwords";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.warren;

        warren = pkgs.rustPlatform.buildRustPackage {
          pname = "warren";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

          # Only what the build needs (keeps target/ etc. out of the store).
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          # Point warren at openvpn from the store, so it works without openvpn installed.
          # --set-default: a WARREN_OPENVPN from the environment still wins.
          postInstall = ''
            wrapProgram $out/bin/warren \
              --set-default WARREN_OPENVPN ${pkgs.openvpn}/bin/openvpn
          '';

          meta = {
            description = "OpenVPN profile manager: many tunnels at once, encrypted saved passwords, TUI and waybar module";
            mainProgram = "warren";
            homepage = "https://github.com/lazicnemanja/warren";
            license = pkgs.lib.licenses.mit;
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            openvpn
          ];
          WARREN_OPENVPN = "${pkgs.openvpn}/bin/openvpn";
        };
      });
    };
}
